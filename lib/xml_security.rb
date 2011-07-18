# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"
require 'rsa_ext'

module XMLSecurity

  class SignedDocument < REXML::Document

    def validate (idp_cert_fingerprint, logger = nil, private_key = nil)
      # get cert from response
      base64_cert             = self.elements["//ds:X509Certificate"].text
      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)

      # check cert matches registered idp cert
      fingerprint             = Digest::SHA1.hexdigest(cert.to_der)
      valid_flag              = fingerprint == idp_cert_fingerprint.gsub(":", "").downcase

      return valid_flag if !valid_flag

      if validate_doc(base64_cert, logger)
        return true
      # elsif private_key
      #   return decode(private_key)
      else
        return false
      end
    end

    def validate_doc(base64_cert, logger)
      # validate references

      # remove signature node
      sig_element = REXML::XPath.first(self, "//ds:Signature", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})
      return false unless sig_element
      sig_element.remove

      #check digests
      REXML::XPath.each(sig_element, "//ds:Reference", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}) do | ref |

        uri                   = ref.attributes.get_attribute("URI").value
        hashed_element        = REXML::XPath.first(self, "//[@ID='#{uri[1,uri.size]}']")
        canoner               = XML::Util::XmlCanonicalizer.new(false, true)
        canon_hashed_element  = canoner.canonicalize(hashed_element)
        hash                  = Base64.encode64(Digest::SHA1.digest(canon_hashed_element)).chomp
        digest_value          = REXML::XPath.first(ref, "//ds:DigestValue", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}).text

        valid_flag            = hash == digest_value

        return valid_flag if !valid_flag
      end

      # verify signature
      canoner                 = XML::Util::XmlCanonicalizer.new(false, true)
      signed_info_element     = REXML::XPath.first(sig_element, "//ds:SignedInfo", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})
      canon_string            = canoner.canonicalize(signed_info_element)

      base64_signature        = REXML::XPath.first(sig_element, "//ds:SignatureValue", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}).text
      signature               = Base64.decode64(base64_signature)

      # get certificate object
      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)

      valid_flag              = cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, canon_string)

      return valid_flag
    end
    
    def decode private_key
      # This is the public key which encrypted the first CipherValue
      cert   = REXML::XPath.first(self, '//ds:X509Certificate')#, 'ds' => "http://www.w3.org/2000/09/xmldsig#")
      c1, c2 = REXML::XPath.match(self, '//xenc:CipherValue', 'xenc' => 'http://www.w3.org/2001/04/xmlenc#')

      cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert.text))
      return false unless cert.check_private_key(private_key)

      # Generate the key used for the cipher below via the RSA::OAEP algo
      rsak      = RSA::Key.new private_key.n, private_key.d
      v1s       = Base64.decode64(c1.text)

      begin
        cipherkey = RSA::OAEP.decode rsak, v1s
      rescue RSA::OAEP::DecodeError
        return false
      end

      # The aes-128-cbc cipher has a 128 bit initialization vector (16 bytes)
      # and this is the first 16 bytes of the raw string.
      bytes  = Base64.decode64(c2.text).bytes.to_a
      iv     = bytes[0...16].pack('c*')
      others = bytes[16..-1].pack('c*')

      cipher = OpenSSL::Cipher.new('aes-128-cbc')
      cipher.decrypt
      cipher.iv  = iv
      cipher.key = cipherkey

      out = cipher.update(others)

      # The encrypted string's length might not be a multiple of the block
      # length of aes-128-cbc (16), so add in another block and then trim
      # off the padding. More info about padding is available at
      # http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html in
      # Section 5.2
      out << cipher.update("\x00" * 16)
      padding = out.bytes.to_a.last
      self.class.new(out[0..-(padding + 1)])
    end

  end
end
