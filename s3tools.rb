#!/opt/bin/ruby
#
# Principes généraux d'encryptage/décryptage:
# ===========================================
#
# Encryptage:
# -----------
# On initialise un chiffrement (cipher) de type 'AES-256-CBC' avec une clé (key)
# et un vecteur d'initialisation (iv) générés aléatoirement. Avec ce chiffrement,
# on encrypte le contenu du fichier à encrypter et on encode le résultat binaire
# en Base64 (ASCII). Ensuite, à l'aide d'une clé publique RSA, on chiffre la clé
# et le vecteur d'initialisation utilisés par le chiffrement. La clé et le vecteur
# d'initialisation cryptés sont ajoutés aprés encodage en Base64 à la fin des données
# cryptées. Enfin, le tout est zippé dans un nouveau fichier de type '.zip'.
#
# [BIN]---/CRYPT/--->[BIN]--->[B64]--->[ZIP]
#
# Décryptage:
# -----------
# On récupère le contenu décompressé du fichier '.zip' et on décode en binaire
# les 3 parties Base64 (ASCII) du contenu du fichier, ces 3 parties correspondant,
# respectivement, aux données, à la clé (key) et au vecteur d'initialisation (iv).
# A l'aide de la clé RSA privée correspondant à la clé RSA publique utilisée lors
# de l'encryptage et de son mot de passe associé, on décrypte la clé (key) et
# le vecteur d'initialisation (iv) précédemment récupérés. Avec la clé et le vecteur
# d'initialisation ainsi décryptés, on initialise un chiffrement (cipher) de type
# 'AES-256-CBC' avec lequel on décrypte le contenu même du fichier. Le contenu
# décrypté est écrit dans un fichier portant le même nom que le fichier '.zip' mais
# sans l'extension '.zip'.
#
# [ZIP]--->[B64]--->[BIN]---/DECRYPT/--->[BIN]
#
# Création d'une paire de clés RSA publique/privée avec openssl:
# --------------------------------------------------------------
# openssl genrsa -des3 -out private.pem 1024
# openssl rsa -in private.pem -out public.pem -outform PEM -pubout
#
# Conversion des clés du format PEM au format DER (pour Java JCE):
# ----------------------------------------------------------------
# openssl rsa -inform PEM -in private.pem -outform DER -pubout -out public.der
# openssl pkcs8 -topk8 -inform PEM -in private.pem -outform DER -nocrypt -out private.der
#
# Lien:
# -----
# http://stuff-things.net/2008/02/05/encrypting-lots-of-sensitive-data-with-ruby-on-rails/
#

require 'aws'
require 'fileutils'
require 'zlib'
require 'zip/zip'
require 'logger'
require 'digest/md5'
require 'yaml'
require 'pp'

include Zlib
include Zip
include FileUtils

FileUtils.mkpath('logs', :mode => 0644)

require 'tools/misctools'
require 'tools/backup'
require 'tools/restore'

include S3Tools

Backup.run

