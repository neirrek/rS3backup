# A class for doing backup of a root directory in a S3 bucket.
class Backup

  include S3Tools

  attr_accessor :bucket_name, :zip_encrypted, :s3

  @@sent_files = []
  @@skipped_files = []

  def Backup.initialize_log
    @@log ||= Logger.new('logs/backup.log', 'daily')
    @@log.level = Logger::INFO
    @@log.datetime_format = '%Y-%m-%d %H:%M:%S'
  end

  # Initialize a backup instance with the given root directory and
  # S3 bucket name.
  def initialize(params)
    Backup.initialize_log
    @bucket_name = params['bucket_name'] || CONFIG['DEFAULT_BUCKET_NAME']
    @type = params['type']
    @root = @current_root = params['root']
    @key_prefix = @current_key_prefix = params['key_prefix']
    @zip_encrypted = params['zip_encrypted']
    @recursive = params['recursive']
    @check_saved = params['check_saved']
    @dirs_filter = (params['dirs_filter'] || []).collect { |f| f.downcase }
    @files_filter = (params['files_filter'] || []).collect { |f| f.downcase }
    @active = params['active']
    @sent_files = []
    @skipped_files = []
  end

  def backup_subdirectories
    @@log.info("Starting backup for directory: #{@root}")
    subdirectories = Dir.entries(@root).select { |entry| File.directory?("#{@root}/#{entry}") && /^(\.|\.\.)$/ !~ entry && !@dirs_filter.include?(entry.downcase) }
    sent_bytes = 0
    start_time = Time.now
    subdirectories.sort.each do |subdirectory|
      @current_root = fullpath(@root, subdirectory)
      @current_key_prefix = key_prefix(subdirectory, @key_prefix, @recursive)
      begin
        sent_bytes += do_backup_directory
      rescue BackupInterruptedException
        @@log.info("Stop required. Exiting!")
        break;
      end
    end
    transfer_rate = compute_transfer_rate(sent_bytes, start_time, Time.now)
    @@log.info("Backup done for directory: #{@root} (#{sent_bytes} bytes uploaded at #{transfer_rate} KB/s)")
  end

  # Backup all the directories of the root directory in the S3 bucket.
  def backup_directory
    @@log.info("Starting backup for directory: #{@root}")
    sent_bytes = 0
    start_time = Time.now
    begin
        sent_bytes += do_backup_directory
    rescue BackupInterruptedException
      @@log.info("Stop required. Exiting!")
    end
    transfer_rate = compute_transfer_rate(sent_bytes, start_time, Time.now)
    @@log.info("Backup done for directory: #{@root} (#{sent_bytes} bytes uploaded at #{transfer_rate} KB/s)")
  end

  def Backup.run(filename = 'config/backups.yml')
    Backup.send_begin_mail
    backups = YAML::load(File.open(filename))
    backups.each do |backup|
      Backup.execute(backup)
    end
    Backup.send_finish_mail
  end

  def Backup.send_begin_mail
    Mailer.send("Your Amazon S3 backup has begun", "The backup of your datas to Amazon S3 is starting now, #{Time.now.strftime('%A %d %b, %Y at %H:%M:%S')}")
  end

  def Backup.send_finish_mail
    body = "The backup of your datas to Amazon S3 has just finished, #{Time.now.strftime('%A %d %b, %Y at %H:%M:%S')}\n\n"
    if @@sent_files.empty?
      body += "No file sent.\n"
    else
      body += "#{@@sent_files.size} files sent:\n"
      body = @@sent_files.inject(body) {|bd, file| bd + " - #{file}\n"}
    end
    if @@skipped_files.empty?
      body += "\nNo file skipped.\n"
    else
      body += "\n#{@@skipped_files.size} files skipped because of upload errors:\n"
      body = @@skipped_files.inject(body) {|bd, file| bd + " - #{file}\n"}
    end
    Mailer.send("Your Amazon S3 backup has finished", body)
  end

  def Backup.execute(params)
    Backup.new(params).execute
  end

  def execute
    return if !@active
    begin
      send("backup_#{@type}")
    rescue NoMethodError
      @@log.error("Unknown backup type: #{@type}")
    rescue Exception => e
      @@log.error("An unexpected error occurred during the backup: #{e.message}")
      @@log.error("Exiting!")
    end
  end

  private

  def do_backup_directory(directory = nil)
    raise BackupInterruptedException.new if backup_interrupted?
    if already_saved?(directory)
      @@log.info("   Directory #{fullpath(@current_root, directory)} already backuped: Skipped.")
      sent_bytes = 0
    else
      sent_bytes = do_backup_files(directory)
      sent_bytes += do_backup_subdirectories(directory) if @recursive
      mark_as_saved(directory)
    end
    return sent_bytes
  end

  def do_backup_subdirectories(directory = nil)
    sent_bytes = 0
    subdirectories = Dir.entries(fullpath(@current_root, directory)).select { |entry| File.directory?("#{fullpath(@current_root, directory, entry)}") && /^(\.|\.\.)$/ !~ entry && !@dirs_filter.include?(entry.downcase) }
    subdirectories.sort.each do |subdirectory|
      sent_bytes += do_backup_directory(fullpath(directory, subdirectory))
    end
    return sent_bytes
  end

  # Backup the given directory of the root directory in the S3 bucket.
  def do_backup_files(directory = nil)
    @@log.info("Starting backup for directory: #{fullpath(@current_root, directory)}")
    key_prefix = key_prefix(directory, @current_key_prefix, @recursive)
    @s3 = initialize_s3
    sent_bytes = 0
    filenames = Dir.entries(fullpath(@current_root, directory)).select { |entry| !File.directory?("#{fullpath(@current_root, directory, entry)}") && !@files_filter.include?(entry.downcase) }
    filenames.sort.each do |filename|
      full_filename = fullpath(@current_root, directory, filename)
      times = 0
      done = File.zero?(full_filename)
      while !done && times <= 3 do
        begin
          sent_bytes += do_backup_file(full_filename, key_prefix)
          done = true
        rescue Exception => e
          times += 1
          if times <= 3
            @@log.info("   Error while sending file: #{full_filename}: #{e.message}")
            @@log.info("   Retrying (#{times}/3)...")
          else
            @@skipped_files << full_filename
            @@log.info("   Skipping file: #{full_filename}")
          end
          @s3 = initialize_s3
        end
      end
    end
    return sent_bytes
  end

  # Backup the file with the given filename, key prefix and S3 interface
  # in the S3 bucket. If no S3 interface is given, a new one is initialized.
  def do_backup_file(filename, key_prefix)
    backup_file_action = BackupFileAction.new(key_prefix, filename, self)
    @@log.info("   Sending file #{filename} to #{@bucket_name}/#{key_prefix}/#{backup_file_action.backup_filename}")
    start_time = Time.now
    filesize = backup_file_action.execute
    if filesize >= 0
      @@sent_files << filename
      transfer_rate = compute_transfer_rate(filesize, start_time, Time.now)
      @@log.info("   File #{filename} sent (#{filesize} bytes uploaded at #{transfer_rate} KB/s)")
    else
      filesize = 0
      @@log.info("   File already backuped: Skipped.")
    end
    return filesize
  end

  def fullpath(root, directory = nil, filename = nil)
    fullpath = root.nil? ? '' : "#{root}/"
    fullpath = directory.nil? ? root : "#{fullpath}#{directory}"
    return filename.nil? ? fullpath : "#{fullpath}/#{filename}"
  end

  def already_saved?(directory)
    return @check_saved && File.exists?(fullpath(@current_root, directory, CONFIG['SAVED_MARK_FILE']))
  end

  def mark_as_saved(directory)
    if @check_saved
      saved_mark_file = fullpath(@current_root, directory, CONFIG['SAVED_MARK_FILE'])
      File.new(saved_mark_file, 'w').close
      # IO.popen("attrib +H #{saved_mark_file}") { |io| io.readlines }
    end
  end

  def backup_interrupted?
    return File.exist?(CONFIG['STOP_FILE'])
  end

  class BackupFileAction

    attr_accessor :bucket_name, :key_prefix, :filename, :zip_encrypted, :backup_filename, :file, :md5

    def initialize(key_prefix, filename, backup)
      @key_prefix = key_prefix
      @filename = filename
      @bucket_name = backup.bucket_name
      @zip_encrypted = backup.zip_encrypted
      @s3 = backup.s3 || initialize_s3
      @backup_filename = compute_backup_filename(filename, @zip_encrypted)
    end

    def execute
      filesize = File.size(@filename)
      if filesize > 0
        @file = @zip_encrypted ? encrypt_zip_file(@filename) : File.open(@filename, 'rb')
        begin
          if backup_needed?
            filesize = File.size(@file.path) if @zip_encrypted
            s3_store_file(@bucket_name, "#{@key_prefix}/#{@backup_filename}", @file, self.md5, @s3)
          else
            filesize = -1
          end
        ensure
          @zip_encrypted ? @file.close(true) : @file.close
        end if !@file.nil?
      end
      return filesize
    end

    def backup_needed?
      bucket = @s3.bucket(@bucket_name)
      key = bucket.key("#{@key_prefix}/#{@backup_filename}")
      return !key.exists? || (!@zip_encrypted && key.e_tag.gsub(/"/, '') != self.md5)
    end

    def md5
      if @md5.nil? && !@file.nil?
        File.open(@file.path, 'rb') do |file|
          @md5 = Digest::MD5.hexdigest(file.read)
        end
      end
      return @md5
    end

    # Encrypt and zip the file with the given filename (e.g. a file with
    # the name xxxxxxxx.zzz will be encrypted and zipped in a file with
    # the name xxxxxxxx.zzz.zip)
    def encrypt_zip_file(filename)
      tempfile = nil
      File.open(filename, 'rb') do |file|
        data = file.read
        if !data.nil? && !data.empty?
          public_key = OpenSSL::PKey::RSA.new(File.read("#{CONFIG['RSA_KEYS_PATH']}/#{CONFIG['RSA_PUBLIC_KEY']}"))
          cipher = OpenSSL::Cipher::Cipher.new(CONFIG['CIPHER_NAME'])
          cipher.encrypt
          cipher.key = cipher_key = cipher.random_key
          cipher.iv = cipher_iv = cipher.random_iv
          encrypted_data = cipher.update(data)
          encrypted_data << cipher.final
          encrypted_data = Base64.encode64(encrypted_data)
          encrypted_data << CONFIG['RSA_KEY_TAG'] + Base64.encode64(public_key.public_encrypt(cipher_key))
          encrypted_data << CONFIG['RSA_IV_TAG'] + Base64.encode64(public_key.public_encrypt(cipher_iv))
          file_basename = File.basename(filename)
          tempfile = Tempfile.new(file_basename, CONFIG['TEMP_DIR'])
          ZipOutputStream::open(tempfile.path) do |zip|
            zip.put_next_entry(file_basename)
            zip.write(encrypted_data)
          end
        end
      end
      return tempfile
    end

  end

  class BackupInterruptedException < Exception; end

end