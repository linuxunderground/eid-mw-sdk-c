bin_PROGRAMS = eid-data get_signmechanisms eid-photo eid-sign eid-waitcard

AM_CFLAGS = $(libbeidpkcs11_CFLAGS)

eid_data_SOURCES = eid-data.c
get_signmechanisms_SOURCES = get_signmechanisms.c
eid_photo_SOURCES = eid-photo.c
eid_photo_LDADD = @JPEG_LIBS@
eid_sign_SOURCES = eid-sign.c
eid_waitcard_SOURCES = eid-waitcard.c

noinst_HEADERS = base.h
