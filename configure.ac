AC_INIT([eid-mw-sdk-c], [0.1.0], [vincent.hardy.be@gmail.com], [eid-mw-sdk-c], [http://github.com/linuxunderground/eid-mw-sdk-c])
AM_INIT_AUTOMAKE([dist-xz])

AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_INSTALL


AC_CHECK_HEADER(rsaref220/unix.h,,AC_MSG_ERROR([required header file missing. Install eid-mw development library first.]))

#TODO: I don't know how to deal with Preprocessor for pkcs11.h
#AC_CHECK_HEADER(rsaref220/pkcs11.h)

AC_CHECK_LIB(beidpkcs11,C_Initialize,,AC_MSG_ERROR([could not find beidpkcs11. Install eid-mw first.]))


AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT