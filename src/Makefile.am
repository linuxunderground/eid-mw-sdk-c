bin_PROGRAMS = eid-data eid-signmechanisms eid-photo eid-sign eid-waitcard eid-x509

AM_CFLAGS = $(libbeidpkcs11_CFLAGS)

eid_data_SOURCES = eid-data.c
eid_signmechanisms_SOURCES = eid-signmechanisms.c
eid_photo_SOURCES = eid-photo.c
eid_photo_LDADD = @JPEG_LIBS@
eid_sign_SOURCES = eid-sign.c utils.c utils.h
eid_sign_LDADD = @SSL_LIBS@
eid_waitcard_SOURCES = eid-waitcard.c
eid_x509_SOURCES = eid-x509.c utils.c utils.h
eid_x509_LDADD = @SSL_LIBS@

noinst_HEADERS = utils.h