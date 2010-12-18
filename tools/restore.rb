# A class for doing restore of a S3 bucket in a root directory.
class Restore

  include S3Tools

  @@keys_mutex = Mutex.new
  @@log_mutex = Mutex.new
  @@bytes_mutex = Mutex.new

  def Restore.initialize_log
    @@log ||= Logger.new('logs/restore.log', 'daily')
    @@log.level = Logger::INFO
    @@log.datetime_format = '%Y-%m-%d %H:%M:%S'
  end

  # Initialize a restore instance with the given root directory and
  # S3 bucket name.
  def initialize(root, bucket_name = CONFIG['DEFAULT_BUCKET_NAME'])
    Restore.initialize_log
    @root = root
    @bucket_name = bucket_name
    @received_bytes = 0
  end

  def slog_info(str)
    @@log_mutex.lock
    @@log.info(str)
    @@log_mutex.unlock
  end

  def next_key(keys)
    @@keys_mutex.lock
    key = keys.slice!(0)
    @@keys_mutex.unlock
    return key
  end

  def received_bytes_add(bytes)
    @@bytes_mutex.lock
    @received_bytes += bytes
    @@bytes_mutex.unlock
  end

  # Restore the given S3 directory into the root directory.
  def restore_directory(directory)
    @@log.info("Starting restore of directory: #{directory} in root: #{@root}")
    if /(\d{4,4})\/(\d{2,2})\/(\d{2,2})\// =~ directory
      dir_pattern = /\d{4,4}\/\d{2,2}\/\d{2,2}\/(.+\.zip)/
      restore_dir = "#{$1}_#{$2}_#{$3}/"
    else
      dir_pattern = /(.+)\/(.+\.zip)/
      restore_dir = directory
    end
    mkdir_p("#{@root}/#{restore_dir}")
    keys = s3_bucket_keys(@bucket_name, directory)
    @@log.info("#{keys.size} files to be restored")
    threads = []
    start_time = Time.now
    [keys.size, 10].min.times do
      threads << Thread.new { restore_keys(restore_dir, keys, dir_pattern) }
    end
    threads.each { |thread| thread.join }
    transfer_rate = compute_transfer_rate(@received_bytes, start_time, Time.now)
    @@log.info("Restore done for directory: #{directory} (#{@received_bytes} bytes downloaded at #{transfer_rate} KB/s)")
  end

  # private

  # Restore a list of keys in the given destination directory using
  # a given directory pattern.
  def restore_keys(directory, keys, dir_pattern)
    s3 = initialize_s3
    while (key = next_key(keys)) do
      dir_pattern =~ key.full_name
      zip_filename = "#{@root}/#{directory}#{$1}"
      slog_info("   Restoring file: #{key.name}")
      done = false; times = 1
      while !done && times <= 3 do
        begin
          start_time = Time.now
          s3_retrieve_file(@bucket_name, key, zip_filename, s3)
          zip_filesize = File.size(zip_filename)
          transfer_rate = compute_transfer_rate(zip_filesize, start_time, Time.now)
          received_bytes_add(zip_filesize)
          done = true
        rescue Exception => e
          slog_info("   Error while retrieving file: #{key.name}: #{e.message}")
          times += 1
          if times <= 3
            slog_info("   Restoring file: #{key.name} (Retrying #{times}/3)")
            s3 = initialize_s3
          end
        end
      end
      decrypt_file(zip_filename)
      slog_info("   File restored: #{key.name} (#{zip_filesize} bytes downloaded at #{transfer_rate} KB/s)")
      rm_f(zip_filename)
    end
  end

  # Decrypt the file with the given filename (typically xxxxxxxx.zzz.zip) and
  # save the result in an another file (typically xxxxxxxx.zzz)
  def decrypt_file(zip_filename)
    zip_content = read_zip_content(zip_filename)
    if zip_content[:data] && zip_content[:key] && zip_content[:iv]
      private_key = OpenSSL::PKey::RSA.new(File.read("#{CONFIG['RSA_KEYS_PATH']}/#{CONFIG['RSA_PRIVATE_KEY']}"), decrypt_password(CONFIG['RSA_PASSWORD']))
      cipher = OpenSSL::Cipher::Cipher.new(CONFIG['CIPHER_NAME'])
      cipher.decrypt
      cipher.key = private_key.private_decrypt(Base64.decode64(zip_content[:key]))
      cipher.iv = private_key.private_decrypt(Base64.decode64(zip_content[:iv]))
      decrypted_data = cipher.update(Base64.decode64(zip_content[:data]))
      decrypted_data << cipher.final
      Regexp.new("(.+)\\.#{CONFIG['ZIP_EXTENSION']}") =~ zip_filename
      File.open($1, 'wb') { |file| file.syswrite(decrypted_data) }
    else
      log.info("Unable to decrypt file: #{zip_filename}")
    end
  end

  # Read the content of a zip file and returns a hash containing the data
  # and the key and initialization vector (iv) used for encryption.
  def read_zip_content(filename)
    zip_content = { :data => '', :key => '', :iv => '' }
    ZipInputStream::open(filename) do |zip|
      zip.get_next_entry
      key_tag_found = false; iv_tag_found = false
      zip.each_line do |line|
        if line == CONFIG['RSA_KEY_TAG']
          key_tag_found = true
        elsif line == CONFIG['RSA_IV_TAG']
          iv_tag_found = true
        elsif !key_tag_found
          zip_content[:data] << line
        elsif !iv_tag_found
          zip_content[:key] << line
        else
          zip_content[:iv] << line
        end
      end
    end
    return zip_content
  end

end