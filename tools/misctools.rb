require 'ensure/encoding'
require 'net/smtp'

class String
  # The extended characters map used by removeaccents. The accented characters
  # are coded here using their numerical equivalent to sidestep encoding issues.
  # These correspond to ISO-8859-1 encoding.
  ACCENTS_MAPPING = {
    'E' => [200,201,202,203],
    'e' => [232,233,234,235],
    'A' => [192,193,194,195,196,197],
    'a' => [224,225,226,227,228,229,230],
    'C' => [199],
    'c' => [231],
    'O' => [210,211,212,213,214,216],
    'o' => [242,243,244,245,246,248],
    'I' => [204,205,206,207],
    'i' => [236,237,238,239],
    'U' => [217,218,219,220],
    'u' => [249,250,251,252],
    'N' => [209],
    'n' => [241],
    'Y' => [221],
    'y' => [253,255],
    'AE' => [306],
    'ae' => [346],
    'OE' => [188],
    'oe' => [189]
  }

  # Remove the accents from the string. Uses String::ACCENTS_MAPPING as the source map.
  def remove_accents
    str = String.new(self).ensure_encoding('UTF-8')
    String::ACCENTS_MAPPING.each do |letter, accents|
      packed = accents.pack('U*')
      rxp = Regexp.new("[#{packed}]")
      str.gsub!(rxp, letter)
    end
    return str
  end

  # Convert a string to a format suitable for a URL without ever using escaped characters.
  # It calls strip, removeaccents, downcase (optional) then removes the spaces (optional)
  # and finally removes any characters matching the default regexp (/[^-_A-Za-z0-9]/).
  #
  # Options
  #
  # * :downcase => call downcase on the string (defaults to false)
  # * :convert_spaces => Convert space to underscore (defaults to true)
  # * :regexp => The regexp matching characters that will be converting to an empty string (defaults to /[^-_A-Za-z0-9]/)
  def urlize
    str = self.strip.remove_accents
    str.gsub!(/\ /,'_')
    str.gsub!(/[^-_\/\.A-Za-z0-9]/, '')
    return str
  end

end

module S3Tools

  CONFIG = YAML::load(File.open('config/config.yml'))

  LOG_S3 = Logger.new('logs/aws.log')
  LOG_S3.level = Logger::ERROR

  Rightscale::HttpConnection.params[:ca_file] = CONFIG['CA_CERT_FILE_PATH']

  # Initialize a new S3 object for connecting to S3.
  def initialize_s3
    return Aws::S3.new(decrypt_password(CONFIG['ACCESS_KEY_ID']), decrypt_password(CONFIG['SECRET_ACCESS_KEY']), :multi_thread => true, :logger => LOG_S3)
  end

  # Compute the S3 key prefix to be used for a given source directory.
  def key_prefix(directory, root_key_prefix = nil, recursive = false)
    key_prefix = directory || ''
    key_prefix = !recursive && /^(.+\/)*(\d{4,4})_(\d{2,2})_(\d{2,2})$/ =~ key_prefix ? "#{$1 ? $1 : ''}#{$2}/#{$3}/#{$4}" : "#{key_prefix}"
    key_prefix = root_key_prefix.nil? ? key_prefix : "#{root_key_prefix}/#{key_prefix}"
    return key_prefix.urlize.gsub(/^(.*)\/$/, '\1')
  end

  # Retrieve the list of the keys in the given S3 bucket. If no S3 instance
  # is given, a new one is initialized.
  def s3_bucket_keys(bucket_name, prefix, s3 = nil)
    s3 ||= S3Tools.initialize_s3
    return s3.bucket(bucket_name).keys(:prefix => prefix)
  end

  # Store a temporary file with a given filename in the given S3 bucket with
  # the given key. If no S3 interface is given, a new one is initialized.
  def s3_store_file(bucket_name, key, file, md5, s3 = nil)
    s3 ||= S3Tools.initialize_s3
    s3.interface.store_object_and_verify(:bucket => bucket_name, :key => key, :md5 => md5, :data => file)
  end

  # Retrieve a file  in a S3 bucket with a given key and save it locally in
  # the given file with the given filename. If no S3 interface is given,
  # a new one is initialized.
  def s3_retrieve_file(bucket_name, key, filename, s3 = nil)
    s3 ||= S3Tools.initialize_s3
    open(filename, 'wb') do |file|
      s3.interface.retrieve_object_and_verify(:bucket => bucket_name, :key => key.name, :md5 => key.e_tag.gsub(/"/, '')) { |chunk| file.write chunk }
    end
  end

  # Decrypt an encrypted password.
  def decrypt_password(password)
    return Inflate.inflate(Base64.decode64(password))
  end

  # Return the name of the backup file on S3 for a given filename and a boolean
  # indicating whether the backup file is zip encrypted or not.
  def compute_backup_filename(filename, zip_encrypted = true)
    return "#{File.basename(filename)}#{zip_encrypted ? '.' + CONFIG['ZIP_EXTENSION'] : ''}".urlize
  end

  # Compute the transfer rate according to a number of transfered bytes, to a start
  # time and to an end time.
  def compute_transfer_rate(transfered_bytes, start_time, end_time)
    return "%.1f" % (transfered_bytes / 1024 / (end_time - start_time))
  end
  
  # A mailer class for sending mails
  class Mailer
  
    @@smtp_server = CONFIG['MAIL_SMTP_SERVER']
    @@from = CONFIG['MAIL_FROM_ADDRESS']
    @@to = CONFIG['MAIL_TO_ADDRESS']
    @@from_who = CONFIG['MAIL_FROM_WHO']
    @@to_who = CONFIG['MAIL_TO_WHO']
  
    def Mailer.send(subject, content)
      message = <<MESSAGE
From: #{@@from_who} <#{@@from}>
To: #{@@to_who} <#{@@to}>
Subject: #{subject}

Hi,

This is an automatic mail sent by Mercure.

#{content}

MESSAGE
      Net::SMTP.start(@@smtp_server) do |smtp|
        smtp.send_message message, @@from, @@to
      end
    end
  
  end

end