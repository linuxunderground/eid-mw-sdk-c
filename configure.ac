AC_INIT([eid-mw-sdk-c], [0.2.2], [vincent.hardy.be@gmail.com], [eid-mw-sdk-c], [http://github.com/linuxunderground/eid-mw-sdk-c])
AM_INIT_AUTOMAKE([dist-xz])


AC_CONFIG_HEADERS([config.h])


AC_PROG_CC
AC_PROG_INSTALL


AC_CHECK_HEADERS([limits.h malloc.h dlfcn.h openssl/bio.h openssl/evp.h openssl/x509.h openssl/pem.h openssl/crypto.h],
  [], [AC_MSG_ERROR([could not find header])])


AC_CHECK_LIB(jpeg, jpeg_mem_src, [HAVE_JPEGLIB=1], [HAVE_JPEGLIB=0])
AC_ARG_ENABLE(jpeg, AS_HELP_STRING([--disable-jpeg], [disregard detection result of libjpeg]),
  [if test $enableval = no; then HAVE_JPEGLIB=0; fi])
if test x$HAVE_JPEGLIB = x1
then
  JPEG_LIBS='-ljpeg'
fi
AM_CONDITIONAL([JPEG], [test x$HAVE_JPEGLIB = x1])
AC_SUBST([JPEG_LIBS])
AC_DEFINE_UNQUOTED([HAVE_JPEGLIB], $HAVE_JPEGLIB, [Define to 1 if you have libjpeg installed])


AC_SEARCH_LIBS([dlopen], [dl],, [AC_MSG_ERROR([I need a dlopen() implementation])])

PKG_CHECK_MODULES(SSL, "openssl", [], [AC_MSG_ERROR([could not find openssl. Install openssl first])])
PKG_CHECK_MODULES([libbeidpkcs11], [libbeidpkcs11], [], [AC_MSG_ERROR([could not find beidpkcs11. Install eid-mw first])])


AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
