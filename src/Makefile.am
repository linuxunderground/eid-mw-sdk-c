bin_PROGRAMS = eid-data eid-signmechanisms eid-photo eid-sign eid-waitcard

AM_CFLAGS = $(libbeidpkcs11_CFLAGS)

eid_data_SOURCES = eid-data.c
eid_signmechanisms_SOURCES = eid-signmechanisms.c
eid_photo_SOURCES = eid-photo.c
eid_photo_LDADD = @JPEG_LIBS@
eid_sign_SOURCES = eid-sign.c
eid_waitcard_SOURCES = eid-waitcard.c

