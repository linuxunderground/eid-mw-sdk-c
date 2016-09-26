bin_PROGRAMS = cert_carddata eid-data get_signmechanisms eid-photo eid-sign wait_card

AM_CFLAGS = $(libbeidpkcs11_CFLAGS)

cert_carddata_SOURCES = cert_carddata.c
eid_data_SOURCES = eid-data.c
get_signmechanisms_SOURCES = get_signmechanisms.c
eid_photo_SOURCES = eid-photo.c
eid_photo_LDADD = @JPEG_LIBS@
eid_sign_SOURCES = eid-sign.c
wait_card_SOURCES = wait_card.c

noinst_HEADERS = base.h cert_registration.h
