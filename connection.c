/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Authors:        Aaron Brady, Shopify (insom)
*/

#include <pcre.h>
#include <glib.h>
#include <string.h>
#include "config.h"
#include "connection.h"

extern char *defaults_file;
#ifdef WITH_SSL
extern char *key;
extern char *cert;
extern char *ca;
extern char *capath;
extern char *cipher;
extern char *tls_version;
extern gboolean ssl;
extern gchar *ssl_mode;
#endif
extern guint compress_protocol;

void configure_connection(MYSQL *conn, const char *name) {
  if (defaults_file != NULL) {
    g_debug("use defaults file: %s", defaults_file);
    mysql_options(conn, MYSQL_READ_DEFAULT_FILE, defaults_file);
  }
  mysql_options(conn, MYSQL_READ_DEFAULT_GROUP, name);

  if (compress_protocol) {
    g_debug("use compress protocol: %d", compress_protocol);
    mysql_options(conn, MYSQL_OPT_COMPRESS, NULL);
  }

#ifdef WITH_SSL
  unsigned int i;
  if (ssl) {
    g_debug("use ssl-mode: %d", ssl);
    i = SSL_MODE_REQUIRED;
    mysql_options(conn, MYSQL_OPT_SSL_MODE, &i);
  } else {
    if (ssl_mode) {
      if (g_ascii_strncasecmp(ssl_mode, "DISABLED", 16) == 0) {
        g_debug("use ssl-mode: DISABLED");
        i = SSL_MODE_DISABLED;
      }
      else if (g_ascii_strncasecmp(ssl_mode, "PREFERRED", 16) == 0) {
        g_debug("use ssl-mode: PREFERRED");
        i = SSL_MODE_PREFERRED;
      }
      else if (g_ascii_strncasecmp(ssl_mode, "REQUIRED", 16) == 0) {
        g_debug("use ssl-mode: REQUIRED");
        i = SSL_MODE_REQUIRED;
      }
      else if (g_ascii_strncasecmp(ssl_mode, "VERIFY_CA", 16) == 0) {
        g_debug("use ssl-mode: VERIFY_CA");
        i = SSL_MODE_VERIFY_CA;
      }
      else if (g_ascii_strncasecmp(ssl_mode, "VERIFY_IDENTITY", 16) == 0) {
        g_debug("use ssl-mode: VERIFY_IDENTITY");
        i = SSL_MODE_VERIFY_IDENTITY;
      }
      else {
        g_critical("Unsupported ssl-mode specified: %s\n", ssl_mode);
        exit(EXIT_FAILURE);
      }
      mysql_options(conn, MYSQL_OPT_SSL_MODE, &i);
    }
  }
  if (key) {
    g_debug("use ssl-key: %s", key);
    mysql_options(conn, MYSQL_OPT_SSL_KEY, key);
  }
  if (cert) {
    g_debug("use ssl-cert: %s", cert);
    mysql_options(conn, MYSQL_OPT_SSL_CERT, cert);
  }
  if (ca) {
    g_debug("use ssl-ca: %s", ca);
    mysql_options(conn, MYSQL_OPT_SSL_CA, ca);
  }
  if (capath) {
    g_debug("use ssl-capath: %s", capath);
    mysql_options(conn, MYSQL_OPT_SSL_CAPATH, capath);
  }
  if (cipher) {
    g_debug("use ssl-cipher: %s", cipher);
    mysql_options(conn, MYSQL_OPT_SSL_CIPHER, cipher);
  }
  if (tls_version) {
    g_debug("use tls-version: %s", tls_version);
    mysql_options(conn, MYSQL_OPT_TLS_VERSION, tls_version);
  }
#endif
}
