# By default, we always build eid-photo. With libjpeg installed, console
# output displays an ASCII picture. Without libjpeg, you get an hexadecimal
# dump.
# If you don't want to build eid-photo when libjpeg is not intalled,
# just uncomment the "if" clause below

bin_PROGRAMS = eid-data eid-signmechanisms eid-sign eid-waitcard eid-x509
#if JPEG
bin_PROGRAMS += eid-photo
#endif

AM_CPPFLAGS = @BEIDPKCS11_CFLAGS@
AM_LDFLAGS = @BEIDPKCS11_LIBS@

eid_data_SOURCES = eid-data.c
eid_data_LDADD = @BEIDPKCS11_LIBS@
eid_signmechanisms_SOURCES = eid-signmechanisms.c
eid_signmechanisms_LDADD = @BEIDPKCS11_LIBS@
eid_photo_SOURCES = eid-photo.c
eid_photo_LDADD = @BEIDPKCS11_LIBS@ @JPEG_LIBS@
eid_sign_SOURCES = eid-sign.c utils.c utils.h
eid_sign_LDFLAGS = $(AM_LDFLAGS) @SSL_LIBS@
eid_sign_LDADD = @BEIDPKCS11_LIBS@ @SSL_LIBS@
eid_waitcard_SOURCES = eid-waitcard.c
eid_waitcard_LDADD = @BEIDPKCS11_LIBS@
eid_x509_SOURCES = eid-x509.c utils.c utils.h
eid_x509_LDFLAGS = $(AM_LDFLAGS) @SSL_LIBS@
eid_x509_LDADD = @BEIDPKCS11_LIBS@ @SSL_LIBS@

noinst_HEADERS = utils.h
