AC_INIT([neosctotp], [1.0.0])
AC_CONFIG_SRCDIR([src/pam_neototp.c])
AM_INIT_AUTOMAKE
LT_INIT
AM_CONFIG_HEADER(config.h)
AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_LIB(neosc,neosc_pcsc_open,,AC_MSG_ERROR([Cannot find libneosc]))
AC_CHECK_LIB(gdbm,gdbm_open,,AC_MSG_ERROR([Cannot find libgdbm]))
AC_CHECK_LIB(pam,pam_get_user,,AC_MSG_ERROR([Cannot find libpam]))
AC_CHECK_HEADERS([libneosc.h],,AC_MSG_ERROR([Cannot find libneosc.h]))
AC_CHECK_HEADERS([gdbm.h security/pam_appl.h security/pam_modules.h])
LIBS=
if test ${libdir} = '${exec_prefix}/lib'
then
	case "`uname -m`" in
	    x86_64|ppc64|s390x|sparc64)
		libdir="/lib64" ;;
	    *)
		libdir="/lib" ;;
	esac
fi
if test ${sysconfdir} = '${prefix}/etc'
then
	sysconfdir="/etc"
fi
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
