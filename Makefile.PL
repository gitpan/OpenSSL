use ExtUtils::MakeMaker;

WriteMakefile(
    'dist'	=> {
	            COMPRESS	=> 'gzip -9v',
	            SUFFIX	=> '.gz',
	           },
    'NAME'		=> 'OpenSSL',
    'VERSION_FROM'	=> 'OpenSSL.pm',
    'LIBS'		=> ['-lssl -lcrypto'],
    'DEFINE'		=> '',
    'INC'		=> '-I.',
    'PM'		=> { 'OpenSSL.pm' => '$(INST_LIBDIR)/OpenSSL.pm',
    			     'OpenSSL/Digest.pm' =>  '$(INST_LIBDIR)/OpenSSL/Digest.pm',
    			     'OpenSSL/Cipher.pm' =>  '$(INST_LIBDIR)/OpenSSL/Cipher.pm',
    			     'OpenSSL/Name.pm' =>  '$(INST_LIBDIR)/OpenSSL/Name.pm',
    			     'OpenSSL/PKCS12.pm' =>  '$(INST_LIBDIR)/OpenSSL/PKCS12.pm',
    			     'OpenSSL/PKCS7.pm' =>  '$(INST_LIBDIR)/OpenSSL/PKCS7.pm',
    			     'OpenSSL/RSA.pm' =>  '$(INST_LIBDIR)/OpenSSL/RSA.pm',
    			     'OpenSSL/Rand.pm' =>  '$(INST_LIBDIR)/OpenSSL/Rand.pm',
    			     'OpenSSL/X509.pm' =>  '$(INST_LIBDIR)/OpenSSL/X509.pm',
    			     'OpenSSL/CRL.pm' =>  '$(INST_LIBDIR)/OpenSSL/CRL.pm',
    			     'OpenSSL/BN.pm' =>  '$(INST_LIBDIR)/OpenSSL/BN.pm',
    			     'OpenSSL/HMAC.pm' =>  '$(INST_LIBDIR)/OpenSSL/HMAC.pm',
                           },
);
