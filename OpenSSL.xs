#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
//#include <openssl/mdc2.h>
#include <openssl/ripemd.h>
#include <openssl/rsa.h>
#include <openssl/sha.h> // fingerprint.
#include <openssl/blowfish.h> // single packet blowfish encoding.
#include <openssl/rand.h>  // random generator.

//#define EDEBUG 1
#ifdef EDEBUG
#define XD(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
#define XD(...)
#endif

static const char *ssl_error(void);

typedef X509           *OpenSSL__X509;
typedef X509_CRL       *OpenSSL__CRL;
typedef X509_NAME      *OpenSSL__Name;
typedef PKCS7          *OpenSSL__PKCS7;
typedef PKCS12         *OpenSSL__PKCS12;
typedef RSA            *OpenSSL__RSA;
typedef EVP_MD_CTX     *OpenSSL__Digest;
typedef EVP_CIPHER_CTX *OpenSSL__Cipher;
typedef BIGNUM	       *OpenSSL__BN;

static inline SV* output_ASN1_INTEGER(ASN1_INTEGER *ai, SV *sv)
{
	if(!ai)
          croak("got 0-ptr");
        if(ai->type != V_ASN1_INTEGER)
          croak("not asn1 integer type (%d)", ai->type);
        //return newSViv(ASN1_INTEGER_get(ai));
        sv_setiv(sv, ASN1_INTEGER_get(ai));
        return sv;
}

static inline SV* output_ASN1_UTCTIME(ASN1_UTCTIME *s, SV *sv)
{
	struct tm tm;
        int offs;
        char buf[64];

	if(!s)
          croak("got 0-ptr");
        if(s->type != V_ASN1_UTCTIME)
          croak("not asn1 utctime type (%d)", s->type);
        if(!ASN1_UTCTIME_check(s))
          croak("invalid UTC time.");
        // fuck openssl crap.
        memset(&tm, 0, sizeof tm);
#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
        tm.tm_year=g2(s->data);
        if(tm.tm_year < 50)
            tm.tm_year+=100;
         tm.tm_mon=g2(s->data+2)-1;
         tm.tm_mday=g2(s->data+4);
         tm.tm_hour=g2(s->data+6);
         tm.tm_min=g2(s->data+8);
         tm.tm_sec=g2(s->data+10);
         if(s->data[12] == 'Z')
              offs=0;
             else
               {
                offs=g2(s->data+13)*60+g2(s->data+15);
                if(s->data[12] == '-')
                    offs= -offs;
               }
#undef g2
             if(!strftime(buf, 63, "%a, %d  %b  %Y %H:%M:%S %z", &tm)) {
               croak("can't convert time.");
             }
          sv_setpv(sv, buf);
          return sv;
}

long bio_write_cb(struct bio_st *bm, int m, const char *ptr, int l, long x, long y)
{
	if(m == BIO_CB_WRITE) {
		SV *sv = (SV *) BIO_get_callback_arg(bm);
                sv_catpvn(sv, ptr, l);
        }
        if(m == BIO_CB_PUTS) {
          	SV *sv = (SV *) BIO_get_callback_arg(bm);
                l = strlen(ptr);
                sv_catpvn(sv, ptr, l);
        }
	return l;
}

static inline BIO* sv_bio_create(void)
{
	SV *sv;
        BIO *bio;
        sv = newSVpvn("",0);
        // mem is completely broken for write, so we use /dev/null
        // and use callbacks-hooks
        bio = BIO_new_file("/dev/null", "wb");
        BIO_set_callback(bio, bio_write_cb);
        BIO_set_callback_arg(bio, (void *)sv);
        return bio;
}

static inline BIO *sv_bio_create_file(SV *filename)
{
        STRLEN l;

        return BIO_new_file(SvPV(filename, l), "wb");
}

static inline SV * sv_bio_final(BIO *bio)
{
     SV* sv;
     
     BIO_flush(bio);
     sv = (SV *) BIO_get_callback_arg(bio);
     BIO_free_all (bio);
     // check for file:
     if(!sv)
      	sv = &PL_sv_undef; 
     return sv;
}

static inline void sv_bio_error(BIO *bio)
{
	SV *sv;
        sv = (SV *) BIO_get_callback_arg(bio);
        if(sv)
		sv_free(sv);
        BIO_free_all (bio);
}

static const char *ssl_error(void) // function leaks. :(
{
	BIO *bio;
        SV *sv;
        STRLEN l;

  	bio = sv_bio_create();
        ERR_print_errors(bio);
        sv = sv_bio_final(bio);
        ERR_clear_error();
        return SvPV(sv, l);	
}

static inline SV* output_BN(BIGNUM *n, SV *sv)
{
  if (!n)
    croak("parse error :)");

  sv_setpvn(sv, BN_bn2dec(n), 0);
  return sv;
}

static const char * digcvt(char *ret, const char *from, int len)
{
	static const char *htab = "0123456789abcdef";
        char *to = ret;
        int i;
        for(i = 0; i < len; i++) {
          *to++ = htab[(*from >> 4) & 0xf];
          *to++ = htab[*from++ & 0xf];
        }
        *to = 0;
        return ret;
}

/* mutt, anything else is broken ! */
static const char B64Chars[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'
};

static unsigned char *mutt_to_base64 (unsigned char *out, const unsigned char *in, size_t len,
		     size_t olen)
{
  char *o = out;
  while (len >= 3 && olen > 10)
  {
    *out++ = B64Chars[in[0] >> 2];
    *out++ = B64Chars[((in[0] << 4) & 0x30) | (in[1] >> 4)];
    *out++ = B64Chars[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
    *out++ = B64Chars[in[2] & 0x3f];
    olen  -= 4;
    len   -= 3;
    in    += 3;
  }

  /* clean up remainder */
  if (len > 0 && olen > 4)
  {
    unsigned char fragment;

    *out++ = B64Chars[in[0] >> 2];
    fragment = (in[0] << 4) & 0x30;
    if (len > 1)
      fragment |= in[1] >> 4;
    *out++ = B64Chars[fragment];
    *out++ = (len < 2) ? '=' : B64Chars[(in[1] << 2) & 0x3c];
    *out++ = '=';
  }
  *out = '\0';
  return o;
}

static inline SV* hexsv(unsigned char *s, unsigned len)
{
        char *ret;
        SV *sv;
        ret = malloc((len<<1)+1);
        if(!ret)
          croak("malloc");
	sv = newSVpv(digcvt(ret, s,len), len <<1);
        free(ret);
        return sv;
}

static inline SV* base64sv(unsigned char *s, unsigned len)
{
        char *ret;
        SV *sv;
        int enc_cnt = ((len+ 2) / 3) << 2;
        ret = malloc(enc_cnt+1);
        if(!ret)
          croak("malloc");
	sv = newSVpv(mutt_to_base64(ret, s,len, enc_cnt+1), enc_cnt);
        free(ret);
        return sv;
        
}

#define FLAG_HEX 0x10
#define FLAG_BASE64 0x20
#define NO_FLAGS(x) ((x) &0xf)

static EVP_MD *_mds[8];

static int mds_booted = 0;

static void mds_boot (void)
{
	if(mds_booted)
          	return;
        mds_booted = 1;
	OpenSSL_add_all_digests();
        _mds[0] = EVP_md2();
        _mds[1] = EVP_md4();
        _mds[2] = EVP_md5();
        _mds[3] = EVP_sha();
        _mds[4] = EVP_sha1();
        _mds[5] = EVP_dss();
        _mds[6] = EVP_dss1();
//      _mds[7] = EVP_mdc2();
        _mds[7] = EVP_ripemd160(); 
}



static char *
dofp(X509 *x509, EVP_MD *digest)
{
   	unsigned char md[EVP_MAX_MD_SIZE];
   	unsigned static char s[EVP_MAX_MD_SIZE*3];
        int n, i;

   	if(!X509_digest(x509, digest, md, &n))
          	croak("Digest error: %s", ssl_error());
        for(i = 0; i < n; i++) {
          sprintf(&s[i*3], "%02X%c", md[i], (i + 1 == (int) n) ? '\0' : ':');
        }
	return s;
}

static inline SV *ol(X509_NAME *x)
{
	char *p;
	SV *sv = newSVpvn("",0);
        X509_NAME_oneline(x, (p=SvGROW(sv,8192)), 8192);
        SvCUR_set(sv, strlen(p));
        return sv;
}

#if 0
static void run_sha1(char *digest, const char *msg, int msglen)
{
        SHA_CTX ctx;
        
       if(!digest || !msg || msglen < 0)
         croak("run_sha1: null pointer or illegal message len");
    	SHA1_Init(&ctx);
        SHA1_Update(&ctx, msg, msglen);
        SHA1_Final(digest, &ctx);	
}
#endif
static bool is_privkey(RSA *key)
{
   return (key->n && key->e && key->d && key->p && key->q
	  && key->dmp1 && key->dmq1 && key->iqmp && key->d) ? 1 : 0;
}

typedef struct {
  EVP_CIPHER *func;
  char name[20];
} cip_list_st;

static cip_list_st cip_list[50];
static int cip_cnt = 0;

static inline char *wappla_fixname(const char *s)
{
	static char x[50];
        char *p;
        strcpy(x, s);
        while((p = strchr(x, '_'))) {
          	*p = '-';
        }
	return x;
}

static inline EVP_CIPHER *lookup_cipher(const char *name)
{
	int i;
        for(i = 0; i < cip_cnt;i++)
          if(!strcmp(name, cip_list[i].name))
            	return cip_list[i].func;
        return 0;
}

#define ADD_C_(x) cip_list[cip_cnt].func =  (EVP_##x()); \
		strcpy(cip_list[cip_cnt++].name, wappla_fixname(#x))

static int cipher_booted = 0;

static void cipher_boot(void)
{
	if(cipher_booted)
          	return;
        cipher_booted++;
	OpenSSL_add_all_ciphers();
#ifndef NO_DES
        ADD_C_(des_ecb);	ADD_C_(des_ede);	ADD_C_(des_ede3);
        ADD_C_(des_cfb);	ADD_C_(des_ede_cfb);	ADD_C_(des_ede3_cfb);
        ADD_C_(des_ofb);	ADD_C_(des_ede_ofb);	ADD_C_(des_ede3_ofb);
        ADD_C_(des_cbc);	ADD_C_(des_ede_cbc);	ADD_C_(des_ede3_cbc);
        ADD_C_(desx_cbc);
#endif
#ifndef NO_RC4
        ADD_C_(rc4);		ADD_C_(rc4_40);
#endif
#ifndef NO_IDEA
        ADD_C_(idea_ecb);	ADD_C_(idea_cfb);
        ADD_C_(idea_ofb);	ADD_C_(idea_cbc);
#endif
#ifndef NI_RC2
        ADD_C_(rc2_ecb);	ADD_C_(rc2_cbc);	ADD_C_(rc2_40_cbc);
        ADD_C_(rc2_64_cbc);	ADD_C_(rc2_cfb);	ADD_C_(rc2_ofb);
#endif
#ifndef NO_BF
        ADD_C_(bf_ecb);		ADD_C_(bf_cbc);
        ADD_C_(bf_cfb);		ADD_C_(bf_ofb);
#endif
#ifndef NO_CAST
        ADD_C_(cast5_ecb);	ADD_C_(cast5_cbc);
        ADD_C_(cast5_cfb);	ADD_C_(cast5_ofb);
#endif
#ifndef NO_RC5
	ADD_C_(rc5_32_12_16_cbc);	ADD_C_(rc5_32_12_16_ecb);
	ADD_C_(rc5_32_12_16_cfb);	ADD_C_(rc5_32_12_16_ofb);
#endif
} 


MODULE = OpenSSL		PACKAGE = OpenSSL::RSA		

OpenSSL::RSA
new_keygen(bits = 128, e = 35)
  	IV bits
	IV e
  CODE:
	if(!(RETVAL = RSA_generate_key(bits, e, NULL, NULL)))
  		croak("RSA_generate_key");
  OUTPUT:
        RETVAL

OpenSSL::RSA
new_pubkey(n, e)
        char *n
        char *e
  CODE:
        RETVAL = RSA_new();
  	if (!RETVAL)
  		croak("can't allocate key");
        if(!(RETVAL->n = BN_new()) || !BN_dec2bn(&RETVAL->n, n)) {
  		RSA_free(RETVAL); croak("can't initialize n");
        }
	if(!(RETVAL->e = BN_new()) || !BN_dec2bn(&RETVAL->e, e)) {
  		RSA_free(RETVAL); croak("can't initialize e");
        }
        //key->p = 0, key->q = 0, key->dmp1 = 0, key->dmq1 = 0, key->iqmp = 0;
  OUTPUT:
        RETVAL
        
        
OpenSSL::RSA
new_privkey(n, e, p, q, dmp1, dmq1, iqmp, d)
        char *n
        char *e
        char *p
        char *q
        char *dmp1
        char *dmq1
        char *iqmp
        char *d
  CODE:
        int rc;

        RETVAL = RSA_new();
  	if (!RETVAL)
  		croak("can't allocate key");
        if(!(RETVAL->n = BN_new()) || !BN_dec2bn(&RETVAL->n, n)) {
  		RSA_free(RETVAL); croak("can't initialize n");
        }
	if(!(RETVAL->e = BN_new()) || !BN_dec2bn(&RETVAL->e, e)) {
  		RSA_free(RETVAL); croak("can't initialize e");
        }
	if(!(RETVAL->p = BN_new()) || !BN_dec2bn(&RETVAL->p, p)) {
  		RSA_free(RETVAL); croak("can't initialize p");
        }
	if(!(RETVAL->q = BN_new()) || !BN_dec2bn(&RETVAL->q, q)) {
  		RSA_free(RETVAL); croak("can't initialize q");
        }
	if(!(RETVAL->dmp1 = BN_new()) || !BN_dec2bn(&RETVAL->dmp1, dmp1)) {
  		RSA_free(RETVAL); croak("can't initialize dmp1");
        }
	if(!(RETVAL->dmq1 = BN_new()) || !BN_dec2bn(&RETVAL->dmq1, dmq1)) {
  		RSA_free(RETVAL); croak("can't initialize dmq1");
        }
	if(!(RETVAL->iqmp = BN_new()) || !BN_dec2bn(&RETVAL->iqmp, iqmp)) {
  		RSA_free(RETVAL); croak("can't initialize iqmp");
        }
	if(!(RETVAL->d = BN_new()) || !BN_dec2bn(&RETVAL->d, d)) {
  		RSA_free(RETVAL); croak("can't initialize d");
        }
	if((rc = RSA_check_key(RETVAL)) != 1) {
  		RSA_free(RETVAL); croak("RSA_check_key failed (%d).", rc);
        }
	OUTPUT:
        RETVAL


void
DESTROY(key)
  OpenSSL::RSA key
  CODE:
  if (key) {
    	  XD("RSA_free(%p)\n", key);
	  RSA_free(key);
  }

IV
keysize(key)
  	OpenSSL::RSA key;
  CODE:
  	if (!key || !key->n)
  		croak("invalid key");
	RETVAL = BN_num_bits(key->n);
OUTPUT:
	RETVAL

bool
check_key(key)
  	OpenSSL::RSA key;
PPCODE:
        if(!key)
  		XSRETURN_NO;
        if(RSA_check_key(key) == 1)
  		XSRETURN_YES;
        XSRETURN_NO;
        

OpenSSL::BN
n(key)
  	OpenSSL::RSA key;
   ALIAS:
   e = 1
   d = 2
   p = 3
   q = 4
   dmp1 = 5
   dmq1 = 6
   iqmp = 7
   CODE:
   RETVAL = 0;
   	if(!key)
  		croak("invalid key");
  switch(ix) {
    case 0: RETVAL = key->n; break;
    case 1: RETVAL = key->e; break;
    case 2: RETVAL = key->d; break;
    case 3: RETVAL = key->p; break;
    case 4: RETVAL = key->q; break;
    case 5: RETVAL = key->dmp1; break;
    case 6: RETVAL = key->dmq1; break;
    case 7: RETVAL = key->iqmp; break;
    default:
      croak("huch");
  }
        if(!RETVAL)
  		croak("bignum not defined (maybe pubkey ?)");
OUTPUT:
	RETVAL


bool
is_privkey(key)
  	OpenSSL::RSA key;
   CODE:
   	RETVAL = is_privkey(key); 
   OUTPUT:
   	RETVAL

void
STORABLE_thaw(osv, cloning, sv)
  SV *osv
  bool cloning
  SV *sv
PREINIT:
  STRLEN len;
  char *p;
  unsigned int *i;
  RSA *key = NULL;
  PPCODE:
  	if(cloning)
  		return;
        i = (unsigned int *) SvPV(sv, len);
        if(i[2] == 0xffffffff) {
          // public key
	  key = RSA_new();
          p = (char *) &i[3];
          key->n =  BN_bin2bn(p, i[0], NULL);
          key->e =  BN_bin2bn(&p[i[0]], i[1], NULL);
        } else if (i[8] == 0xffffffff) {
          // private key
       	  key = RSA_new();
          p = (char *) &i[9];
	  key->n = BN_bin2bn(p, i[0], NULL);
          p += i[0];
          key->e = BN_bin2bn(p, i[1], NULL);
          p += i[1];
          key->d = BN_bin2bn(p, i[2], NULL);
          p += i[2];
          key->p = BN_bin2bn(p, i[3], NULL);
          p += i[3];
          key->q = BN_bin2bn(p, i[4], NULL);
          p += i[4];
          key->dmp1 = BN_bin2bn(p, i[5], NULL);
          p += i[5];
          key->dmq1 = BN_bin2bn(p, i[6], NULL);
          p += i[6];
          key->iqmp = BN_bin2bn(p, i[7], NULL);
        }
	if(!key)
          croak("Illegal Storable format.");
          sv_setiv(SvRV(osv), (IV) key);
          //sv_setref_pv(SvRV(osv), "OpenSSL::RSA", newRV_noinc((void *) key);
          //sv_setiv(osv, (IV) key);
	


void
STORABLE_freeze(key, cloning)
  	OpenSSL::RSA key
        bool cloning
PREINIT:
        STRLEN totlen;
PPCODE:
	if(cloning)
  		return;
        totlen = BN_num_bytes(key->n) + BN_num_bytes(key->e) + 3*sizeof(int);
        if(!is_privkey(key)) {
		int *y = malloc(totlen);
                int *x = y;
                char *p;
		*x++ = BN_num_bytes(key->n);
                *x++ = BN_num_bytes(key->e);
                *x++ = 0xffffffff;
                p = (char *) x;
                p += BN_bn2bin(key->n, p);
                p += BN_bn2bin(key->e, p);
                XPUSHs(sv_2mortal(newSVpvn((char *)y, p - (char *) y)));
                free(y);
        } else {
		int *y, *x;
                char *p;
                totlen += BN_num_bytes(key->d)
                  + BN_num_bytes(key->p)
                  + BN_num_bytes(key->q)
                  + BN_num_bytes(key->dmp1)
                  + BN_num_bytes(key->dmq1)
                  + BN_num_bytes(key->iqmp) + 6*sizeof(int);
		y = malloc(totlen);
                x = y;
		*x++ = BN_num_bytes(key->n);
                *x++ = BN_num_bytes(key->e);
		*x++ = BN_num_bytes(key->d);
                *x++ = BN_num_bytes(key->p);
		*x++ = BN_num_bytes(key->q);
                *x++ = BN_num_bytes(key->dmp1);
                *x++ = BN_num_bytes(key->dmq1);
                *x++ = BN_num_bytes(key->iqmp);
                *x++ = 0xffffffff;
                p = (char *) x;
                p += BN_bn2bin(key->n, p);
                p += BN_bn2bin(key->e, p);
                p += BN_bn2bin(key->d, p);
                p += BN_bn2bin(key->p, p);
                p += BN_bn2bin(key->q, p);
                p += BN_bn2bin(key->dmp1, p);
                p += BN_bn2bin(key->dmq1, p);
                p += BN_bn2bin(key->iqmp, p);
                XPUSHs(sv_2mortal(newSVpvn((char *)y, p - (char *) y)));
                free(y);
        }
        

SV *
public_encrypt(key, sv)
	OpenSSL::RSA key;
        SV *sv;
   ALIAS:
   encrypt = 4
   public_decrypt = 1
   verify = 5
   private_encrypt = 2
   sign = 6
   private_decrypt = 3
   decrypt = 7
   PREINIT:
   static int (*func[4])(int, unsigned char *, unsigned char *, RSA *, int) = { RSA_public_encrypt, RSA_public_decrypt, RSA_private_encrypt, RSA_private_decrypt };
   STRLEN len;
   int keylen;
   char *p;
   char *out;
   STRLEN rc;
   CODE:
   	if(!SvPOK(sv))
  		croak ("need a string.");
   	p = SvPV(sv, len);
        keylen = BN_num_bits(key->n);
        if(!p || len < 1 || (len*8 > (keylen+7)&~0x7))
  		croak("illegal value");
        RETVAL = NEWSV(0, len + keylen);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, len + keylen);
        out = SvPV_nolen(RETVAL);
        if((ix&0x3) > 1 && !is_privkey(key))
                croak("need a private key.");
        rc = func[ix&0x3](len, p, out, key, RSA_PKCS1_PADDING);
        if(rc < 0) {
          	sv_free(RETVAL);
                RETVAL = &PL_sv_undef;
  		croak("crypto error... rc=%d inlen=%d", rc, len);
        }
        SvCUR_set(RETVAL, rc);
   OUTPUT:
   	RETVAL


void
fingerprint(key)
    OpenSSL::RSA key
    PREINIT:
         char *x;
         char dig[SHA_DIGEST_LENGTH];
         int nlen, elen;
    PPCODE:
        nlen = BN_num_bytes(key->n);
        elen = BN_num_bytes(key->e);
        x = malloc(nlen + elen);
        if(!x)
  		croak("malloc error");
        BN_bn2bin(key->n, x);
        BN_bn2bin(key->e, &x[nlen]);
        //un_sha1(dig, x, nlen+elen);	
        free(x);
        XPUSHs(sv_2mortal(newSVpvn(dig, SHA_DIGEST_LENGTH)));
         
MODULE = OpenSSL		PACKAGE = OpenSSL::Name

PROTOTYPES: ENABLE

OpenSSL::Name
new(class)
	SV	*class
  CODE:
  	if(!(RETVAL = X509_NAME_new())) {
                croak("X509_NAME_new");
        }
  OUTPUT:
        RETVAL


void
add(name, key, string)
  OpenSSL::Name name
  SV *key
  SV *string
  PREINIT:
        STRLEN l, kl;
        char *p, *k;
        int ok;
  PPCODE:
        p = SvPV(string, l);
        if(SvIOK(key)) {
          ok = X509_NAME_add_entry_by_NID(name, SvIV(key), MBSTRING_ASC, p, -1, -1, 0);
        } else {
          k = SvPV(key, kl);
          ok = X509_NAME_add_entry_by_txt(name, k, MBSTRING_ASC, p, -1, -1, 0);
        }
	if(!ok)
          croak("X509_NAME_add_entry_by_*: %s", ssl_error());

IV
count(name)
 	OpenSSL::Name name
    CODE:
    	RETVAL = X509_NAME_entry_count(name);
    OUTPUT:
    	RETVAL

void
getall(name)
  	OpenSSL::Name name
   PREINIT:
   	int cnt, i;
        X509_NAME_ENTRY *e;
        int nid;
        ASN1_STRING *s;
    PPCODE:
    	cnt = X509_NAME_entry_count(name);
   	EXTEND(SP, cnt<<1);
        for(i = 0; i < cnt; i++) {
          e = X509_NAME_get_entry(name, i);
	  if(!e)
            	croak("X509_NAME_get_entry");
          nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
          s = X509_NAME_ENTRY_get_data(e);
          PUSHs(sv_2mortal(newSVpv(OBJ_nid2ln(nid),0)));
          PUSHs(sv_2mortal(newSVpvn(s->data, s->length)));
        }
	   
void
DESTROY(name)
  	OpenSSL::Name name
    CODE:
  	if(name) {
          	XD("X509_NAME_free(%p)\n", name);
  		X509_NAME_free(name);
        }


MODULE = OpenSSL          PACKAGE = OpenSSL::Rand

PROTOTYPES: ENABLE

BOOT:
{
       int fd;
       int rc;
       ERR_load_RAND_strings();
       fd = open("/dev/urandom", O_RDONLY);
       if(fd != -1) {
            char buf[64];
            rc = read(fd, buf, 64);
            if(rc < 1) {
                warn ("read /dev/urandom");
            } else {
                RAND_seed(buf, rc);
            }
            close(fd);
       } else {
          warn ("can't open /dev/urandom");
       }
}

       

SV *
randbytes(nr)
  IV nr
  ALIAS:
  	randbytes_hex = 1
        randbytes_base64 = 2
  PREINIT:
  	char *p;
        int rc;
  CODE:
  	p = malloc(nr+1);
        if(!p)
  	   croak("malloc failed");
        rc = RAND_bytes(p, nr);
        if(rc != 1) {
           free(p);
  	   croak("RAND_bytes returned %d", rc);
        }
	switch(ix) {
          case 0:
        	RETVAL = newSVpvn(p, nr);
                break;
          case 1:
                RETVAL = hexsv(p, nr);
                break;
          default:
                RETVAL = base64sv(p, nr);
                break;
        }
        free(p);
  OUTPUT:
  	RETVAL

        
MODULE = OpenSSL		PACKAGE = OpenSSL::X509

PROTOTYPES: ENABLE

BOOT:
{
	// We have joy we have fun we have seasons in the sun...
	OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
        SSL_load_error_strings();
	ERR_load_PEM_strings();
        ERR_load_PKCS7_strings();
        ERR_load_PKCS12_strings();
        ERR_load_ASN1_strings();
        ERR_load_crypto_strings();
        ERR_load_RAND_strings();
        ERR_load_X509_strings();
        ERR_load_X509V3_strings();
        ERR_load_DH_strings();
        ERR_load_DSA_strings();
        ERR_load_RSA_strings();
}


OpenSSL::X509
new(class)
	SV	*class
	CODE:
  	if ((RETVAL = X509_new ()) == NULL)
  		croak("X509_new");

        if (!X509_set_version (RETVAL, 2))
          {
   	    X509_free (RETVAL);
            croak ("X509_set_version");
          }

	ASN1_INTEGER_set (X509_get_serialNumber (RETVAL), 0L);
	OUTPUT:
        RETVAL
  

OpenSSL::X509
new_from_string(class,thing)
	SV	*class
        SV	*thing
    ALIAS:
   	new_from_file = 1     
  PREINIT:
  	BIO *bio;
        STRLEN l;
        char *p;
  CODE:
	p = SvPV (thing, l);
        if(ix == 1) {
          	bio = BIO_new_file(p, "r");
        } else {
        	bio = BIO_new_mem_buf (p, l);
        }
	if(!bio) 
  		croak(ssl_error());

        RETVAL = PEM_read_bio_X509 (bio, 0, 0, 0);
        BIO_free (bio);
        if(!RETVAL)
  		croak("PEM_read_bio_X509: %s", ssl_error());

  OUTPUT:
        RETVAL

void
DESTROY(x509)
  OpenSSL::X509 x509
  CODE:
  	if (x509) {
          	XD("X509_free(%p)\n", x509);
	  	X509_free (x509);
                x509 = 0;
        }


char *
fingerprint_md5(x509)
	OpenSSL::X509 x509
   ALIAS:
   	fingerprint_md2 = 1
        fingerprint_sha1 = 2
   PREINIT:
   	EVP_MD *mds[] = { EVP_md5(), EVP_md2(), EVP_sha1() };
   CODE:                     
   	RETVAL = dofp(x509, mds[ix]);
   OUTPUT:
	RETVAL


OpenSSL::Name 
subject(x509)
  OpenSSL::X509 x509
  CODE:
  	RETVAL = X509_NAME_dup (X509_get_subject_name(x509));
  OUTPUT:
  	RETVAL

OpenSSL::Name 
issuer(x509)
  OpenSSL::X509 x509
  CODE:
  	RETVAL = X509_NAME_dup (X509_get_issuer_name(x509));
  OUTPUT:
  	RETVAL

        
SV *
subject_txt(x509)
  	OpenSSL::X509 x509
    CODE:
        RETVAL = ol(X509_get_subject_name(x509));
    OUTPUT:
    	RETVAL


SV *
issuer_txt(x509)
  	OpenSSL::X509 x509
    CODE:
        RETVAL = ol(X509_get_issuer_name(x509));
    OUTPUT:
    	RETVAL

ASN1_INTEGER *
serial(x509)
  	OpenSSL::X509 x509
    CODE:
    	RETVAL = X509_get_serialNumber(x509);
    OUTPUT:
    	RETVAL

        
int
version(x509)
  	OpenSSL::X509 x509
    CODE:
    	RETVAL = X509_get_version(x509);
    OUTPUT:
    	RETVAL

ASN1_UTCTIME *
notBefore(x509)
  	OpenSSL::X509 x509
    CODE:
    	RETVAL = X509_get_notBefore(x509);
    OUTPUT:
    	RETVAL
        
ASN1_UTCTIME *
notAfter(x509)
  	OpenSSL::X509 x509
    CODE:
    	RETVAL = X509_get_notAfter(x509);
    OUTPUT:
    	RETVAL

int
cert_type(x509)
  	OpenSSL::X509 x509
    CODE:
    	RETVAL = X509_certificate_type(x509, 0);
    OUTPUT:
    	RETVAL

SV*
as_string(x509,...)
  	OpenSSL::X509 x509
        ALIAS:
	as_file = 1
        PROTOTYPE: $;$
    PREINIT:
    	BIO *bio;
    CODE:
        if((ix != 1 && items > 1) || (ix == 1 && items != 2))
              croak("OpenSSL::X509::%s: illegal/missing args", (ix == 1) ? "as_file" : " as_string");
        if(items > 1) { 
              bio = sv_bio_create_file(ST(1));
        } else {
             bio = sv_bio_create();
        }
        if(!bio)
                  croak("sv_bio_create");
        if(!PEM_write_bio_X509(bio, x509)) {
          	sv_bio_error(bio);
          	croak("PEM_write_bio_X509: %s", ssl_error());
        }
        RETVAL = sv_bio_final(bio);
    OUTPUT:
    	RETVAL

SV*
info(x509)
  	OpenSSL::X509 x509
   PREINIT:
   	BIO *bio;
   CODE:
   	bio = sv_bio_create();
        if(!X509_print(bio,x509)) {
          	sv_bio_error(bio);
          	croak("X509_print: %s", ssl_error());
        }
	RETVAL = sv_bio_final(bio);
OUTPUT:
       RETVAL

void
set_issuer(x509,name)
  	OpenSSL::X509 x509
  	OpenSSL::Name name
  CODE:
  	X509_set_issuer_name(x509, X509_NAME_dup(name));

void
set_subject(x509,name)
  	OpenSSL::X509 x509
        OpenSSL::Name name
  CODE:
  	X509_set_subject_name(x509, X509_NAME_dup(name));

SV *
errstring(x509)
  	OpenSSL::X509 x509
  PREINIT:
  	BIO *bio;
  CODE:
  	bio = sv_bio_create();
        ERR_print_errors(bio);
        RETVAL = sv_bio_final(bio);
        ERR_clear_error();
  OUTPUT:
  	RETVAL
        
        
MODULE = OpenSSL		PACKAGE = OpenSSL::Cipher

PROTOTYPES: ENABLE 

BOOT:
{
	cipher_boot();
}

void
DESTROY(ctx)
  	OpenSSL::Cipher ctx
  CODE:
  	if(ctx) {
		EVP_CIPHER_CTX_cleanup(ctx);
  		free(ctx);
        }

OpenSSL::Cipher
new_decrypt(...)
  ALIAS:
  	new_encrypt = 1
  PREINIT:
  	char *name;
        SV *svkey;
  	EVP_CIPHER *ci;
	char *key;
        char iv[EVP_MAX_IV_LENGTH];
        char k[EVP_MAX_KEY_LENGTH];
        int rc;
        STRLEN keylen;
  CODE:
  	if(items < 2 || items > 3) {
          	croak("usage: new_[en|de]crypt(ciphname,key)");
        }
	name = SvPV_nolen(ST(items -2));
	svkey = ST(items - 1);
        memset(iv, 0, EVP_MAX_IV_LENGTH);
        memset(k, 0, EVP_MAX_KEY_LENGTH);
  
  	if(!(ci = lookup_cipher(name)))
  		croak("OpenSSL::Cipher::new: no such cipher \"%s\"", name);
        RETVAL = (EVP_CIPHER_CTX *) malloc(sizeof(EVP_CIPHER_CTX));
        if(!RETVAL)
  		croak("malloc error");
        key = SvPV(svkey, keylen);
	memcpy(k, key, (keylen <= ci->key_len) ? keylen : ci->key_len);
        rc = EVP_CipherInit(RETVAL, ci, k, iv, ix);
        memset(iv, 0, EVP_MAX_IV_LENGTH);
        //@@@ memset(k, 0, EVP_MAX_KEY_LENGTH);
        if(!rc) {
          free(RETVAL);
          croak("EVP_CipherInit");
        }
  OUTPUT:
        RETVAL


SV *
update(ctx,svin)
	OpenSSL::Cipher ctx
        SV		*svin
  PREINIT:
  	unsigned char *in, *out;
        STRLEN il, ol;
     CODE:
     	in = SvPV(svin, il);
        ol = (il + 63) & ~63;
        RETVAL = NEWSV(0, ol);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, ol);
        out = SvPV_nolen(RETVAL);
        if(!EVP_CipherUpdate(ctx, out, &ol, in, il)) {
          	sv_free(RETVAL);
  		croak("EVP_CipherUpdate");
        }
	SvCUR_set(RETVAL, ol);
    OUTPUT:
    	RETVAL

SV *
final(ctx)
  OpenSSL::Cipher ctx
  PREINIT:
    	STRLEN ol;
        unsigned char *out;
     CODE:
     	ol = 256;
	RETVAL = NEWSV(0, ol);
        SvPOK_only(RETVAL);
        SvCUR_set(RETVAL, ol);
        out = SvPV_nolen(RETVAL);
        if(!out)
  		croak("memory");
        if(!EVP_CipherFinal(ctx, out, &ol)) {
          sv_free(RETVAL);
          croak("EVP_CipherFinal %s", ssl_error());
        }
	SvCUR_set(RETVAL, ol);
     OUTPUT:
     	RETVAL

void
enum_ciphers()
  PREINIT:
  	int i;
   PPCODE:
   	EXTEND(SP, cip_cnt<<1);
        for(i = 0; i < cip_cnt; i++) {
          PUSHs(sv_2mortal(newSVpv(cip_list[i].name, 0)));
          PUSHs(sv_2mortal(newSViv(cip_list[i].func->key_len)));
        }


        

MODULE = OpenSSL		PACKAGE = OpenSSL::Digest

PROTOTYPES: ENABLE 

BOOT:
{
	mds_boot();
}

SV *
md2(...)
  ALIAS:
  	md4 =       0x1
        md5 =       0x2
        sha =       0x3
        sha1 =      0x4
        dss =       0x5
        dss1 =      0x6
        mdc2 =      0x7
        ripemd160 = 0x8
	md2_hex =   0x10
  	md4_hex =   0x11
        md5_hex =   0x12
        sha_hex =   0x13
        sha1_hex =  0x14
        dss_hex =   0x15
        dss1_hex =  0x16
        mdc2_hex =  0x17
        ripemd160_hex = 0x18
	md2_base64 = 0x20
  	md4_base64 = 0x21
        md5_base64 = 0x22
        sha_base64 = 0x23
        sha1_base64 = 0x24
        dss_base64 = 0x25
        dss1_base64 = 0x26
        mdc2_base64 = 0x27
        ripemd160_base64 = 0x28
     CODE:
  	EVP_MD_CTX ctx;
	STRLEN l;
        char *p;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        int i;

     	EVP_DigestInit(&ctx, _mds[NO_FLAGS(ix)]);

        for (i = 0; i < items; i++)
          {
            p = SvPV(ST(i), l);
            EVP_DigestUpdate(&ctx, p, l);
          }

        EVP_DigestFinal(&ctx, md, &md_len);
        switch(ix & ~15) {
          case 0:
            	RETVAL = newSVpvn(md, md_len);
	  	break;
          case FLAG_HEX:
                RETVAL = hexsv(md, md_len);
                break;
          default:
                RETVAL = base64sv(md, md_len);
		break;
        }
    OUTPUT:
    	RETVAL

        
OpenSSL::Digest
new_md2()
  ALIAS:
  	new_md4 = 0x1
        new_md5 = 0x2
        mew_sha = 0x3
        new_sha1 = 0x4
        new_dss = 0x5
        new_dss1 = 0x6
        new_mdc2 = 0x7
        new_ripemd160 = 0x8
   CODE:
   	RETVAL = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
	if(!RETVAL)
  		croak("out of memory.");
     	EVP_DigestInit(RETVAL, _mds[NO_FLAGS(ix)]);
   OUTPUT:
   	RETVAL

void
DESTROY(ctx)
  OpenSSL::Digest ctx
  CODE:
  	if(ctx)
  		free(ctx);
         
void
update(ctx, ...)
	OpenSSL::Digest ctx
    PREINIT:
    	STRLEN l;
        char *p;
        int i;
    CODE:
        for (i = 1; i < items; i++)
          {
            p = SvPV(ST(i), l);
            EVP_DigestUpdate(ctx, p, l);
          }

SV *
final(ctx)
  	OpenSSL::Digest ctx
   ALIAS:
	final_hex = 1
        final_base64 = 2
   PREINIT:
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len;
      CODE:
      	EVP_DigestFinal(ctx, md, &md_len);
        switch(ix) {
          case 0:
            	RETVAL = newSVpvn(md, md_len);
            	break;
          case 1:
                RETVAL = hexsv(md, md_len);
                break;
          default:
                RETVAL = base64sv(md, md_len);
		break;
        }
    OUTPUT:
    	RETVAL
        
MODULE = OpenSSL::Digest		PACKAGE = OpenSSL::HMAC

PROTOTYPES: ENABLE 

BOOT:
{
	mds_boot();
}

SV *
md2(svkey, sv)
  SV *svkey
  SV *sv
  ALIAS:
  	md4 =       0x1
        md5 =       0x2
        sha =       0x3
        sha1 =      0x4
        dss =       0x5
        dss1 =      0x6
        mdc2 =      0x7
        ripemd160 = 0x8
	md2_hex =   0x10
  	md4_hex =   0x11
        md5_hex =   0x12
        sha_hex =   0x13
        sha1_hex =  0x14
        dss_hex =   0x15
        dss1_hex =  0x16
        mdc2_hex =  0x17
        ripemd160_hex = 0x18
	md2_base64 = 0x20
  	md4_base64 = 0x21
        md5_base64 = 0x22
        sha_base64 = 0x23
        sha1_base64 = 0x24
        dss_base64 = 0x25
        dss1_base64 = 0x26
        mdc2_base64 = 0x27
        ripemd160_base64 = 0x28
  PREINIT:
	STRLEN l, keylen;
        char *p;
        char *key;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len;
     CODE:
        p = SvPV(sv, l);
        key = SvPV(svkey, keylen);
     	if(!HMAC(_mds[NO_FLAGS(ix)], key, keylen, p, l, md, &md_len))
  		croak("HMAC");
        switch(ix & ~15) {
          case 0:
            	RETVAL = newSVpvn(md, md_len);
	  	break;
          case FLAG_HEX:
                RETVAL = hexsv(md, md_len);
                break;
          default:
                RETVAL = base64sv(md, md_len);
		break;
        }
    OUTPUT:
    	RETVAL

        
OpenSSL::Digest
new_md2()
  ALIAS:
  	new_md4 = 0x1
        new_md5 = 0x2
        mew_sha = 0x3
        new_sha1 = 0x4
        new_dss = 0x5
        new_dss1 = 0x6
        new_mdc2 = 0x7
        new_ripemd160 = 0x8
   CODE:
   	RETVAL = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
	if(!RETVAL)
  		croak("out of memory.");
     	EVP_DigestInit(RETVAL, _mds[NO_FLAGS(ix)]);
   OUTPUT:
   	RETVAL

void
DESTROY(ctx)
  OpenSSL::Digest ctx
  CODE:
  	if(ctx)
  		free(ctx);
         
void
update(ctx, ...)
	OpenSSL::Digest ctx
    PREINIT:
    	STRLEN l;
        char *p;
        int i;
    CODE:
        for (i = 1; i < items; i++)
          {
            p = SvPV(ST(i), l);
            EVP_DigestUpdate(ctx, p, l);
          }

SV *
final(ctx)
  	OpenSSL::Digest ctx
   ALIAS:
	final_hex = 1
        final_base64 = 2
   PREINIT:
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len;
      CODE:
      	EVP_DigestFinal(ctx, md, &md_len);
        switch(ix) {
          case 0:
            	RETVAL = newSVpvn(md, md_len);
            	break;
          case 1:
                RETVAL = hexsv(md, md_len);
                break;
          default:
                RETVAL = base64sv(md, md_len);
		break;
        }
    OUTPUT:
    	RETVAL
        

MODULE = OpenSSL		PACKAGE = OpenSSL::PKCS7
        
OpenSSL::PKCS7
new()
  CODE:
  	if(!(RETVAL = PKCS7_new())) {
                croak("PKCS7_new");
        }
  OUTPUT:
        RETVAL


void
DESTROY(p7)
  	OpenSSL::PKCS7 p7;
   CODE:
   	if(p7) {
     		XD("PKCS7_free(%p)\n", p7);
  		PKCS7_free(p7);
        }

                
MODULE = OpenSSL		PACKAGE = OpenSSL::PKCS12
        
OpenSSL::PKCS12
new(class)
        SV	*class
  CODE:
  	if(!(RETVAL = PKCS12_new())) {
                croak("PKCS12_new");
        }
  OUTPUT:
        RETVAL

OpenSSL::PKCS12
new_from_string(class,sv)
        SV	*class
        SV *sv
        ALIAS:
        new_from_file = 1
   PREINIT:
        BIO *bio;
        char *s;
        STRLEN len;
   CODE:
      	s = SvPV(sv, len);
        if(ix == 1) {
          	bio = BIO_new_file(s, "r");
        } else {
        	bio = BIO_new_mem_buf (s, len);
        }
        if(!bio)
          croak("BIO_new_mem_buf");
        if(!(RETVAL = d2i_PKCS12_bio(bio, 0))) {
		BIO_free(bio);
         	croak("d2i_PKCS12_BIO: %s", ssl_error());
         }
	BIO_free(bio);
   OUTPUT:
   	RETVAL
            

SV*
mac_ok(p12, pwd)
  	OpenSSL::PKCS12 p12
        char *pwd
   CODE:
   	
   	RETVAL = (PKCS12_verify_mac(p12, pwd, strlen(pwd))) ? &PL_sv_yes : &PL_sv_no;
  OUTPUT:
   	RETVAL

void
changepass(p12, oldpwd, newpwd)
  	OpenSSL::PKCS12 p12
        SV *oldpwd
        SV *newpwd
    PREINIT:
    	char *op = 0;
        char *np = 0;
    CODE:
    	if(oldpwd != &PL_sv_undef)
  		op = SvPV_nolen(oldpwd);
    	if(newpwd != &PL_sv_undef)
  		np = SvPV_nolen(newpwd);
    	if(!PKCS12_newpass(p12, op, np)) {
      		croak("PKCS12_newpass: %s", ssl_error());
    	}

SV*        
as_string(p12,...)
  	OpenSSL::PKCS12 p12
        ALIAS:
        as_file = 1
        PROTOTYPE: $;$
  PREINIT:
        BIO *bio;
     CODE:
     	if((ix != 1 && items > 1) || (ix == 1 && items != 2))
            croak("OpenSSL::PKCS12::%s: illegal/missing args", (ix == 1) ? "as_file" : "as_string");
   	if(items > 1) {
   	   bio = sv_bio_create_file(ST(1));
        } else {
           bio = sv_bio_create();
        }
	if(!bio)
  		croak("sv_bio_create");
        if(!i2d_PKCS12_bio(bio, p12)) {
          	sv_bio_error(bio);
                croak("i2d_PKCS12_bio: %s", ssl_error());
        }
	RETVAL = sv_bio_final(bio);
     OUTPUT:
     	RETVAL

void
DESTROY(p12)
  	OpenSSL::PKCS12 p12;
   CODE:
   	if(p12) {
     		XD("PKCS12_free(%p)\n", p12);
  		PKCS12_free(p12);
   	}


MODULE = OpenSSL		PACKAGE = OpenSSL::CRL

OpenSSL::CRL
new_from_string(class,thing)
  	SV *class
        SV *thing
    ALIAS:
   	new_from_file = 1     
  PREINIT:
  	BIO *bio;
        STRLEN l;
        char *p;
  CODE:
	p = SvPV(thing, l);
        if(ix == 1) {
          	bio = BIO_new_file(p, "r");
        } else {
        	bio = BIO_new_mem_buf (p, l);
        }
	if(!bio) 
  		croak(ssl_error());

        RETVAL = PEM_read_bio_X509_CRL (bio, 0, 0, 0);
        BIO_free (bio);
        if(!RETVAL)
  		croak("PEM_read_bio_X509_CRL: %s", ssl_error());

  OUTPUT:
        RETVAL

void
DESTROY(crl)
  OpenSSL::CRL crl
  CODE:
  	if (crl) {
     		XD("X509_CRL_free (%p)\n", crl);
	  	X509_CRL_free(crl);
                crl = 0;
        }

SV*
info(crl)
  	OpenSSL::CRL crl
   PREINIT:
   	BIO *bio;
   CODE:
   	bio = sv_bio_create();
        if(!X509_CRL_print(bio,crl)) {
          	sv_bio_error(bio);
          	croak("X509_CRL_print: %s", ssl_error());
        }
	RETVAL = sv_bio_final(bio);
OUTPUT:
       RETVAL

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"



MODULE = OpenSSL		PACKAGE = OpenSSL::BN		

OpenSSL::BN
new(class,...)
  	SV *class
    CODE:
        unsigned char *p;
    	RETVAL = BN_new();
	BN_init(RETVAL);
        if(items == 2) {
          p = SvPV(ST(1), PL_na);
  	  BN_dec2bn(&RETVAL, p);
        } else {
          BN_zero(RETVAL);
        }
    OUTPUT:
    	RETVAL

OpenSSL::BN
clone(bn)
  	OpenSSL::BN bn
    CODE:
    	RETVAL = BN_dup(bn);
    OUTPUT:
    	RETVAL
        
OpenSSL::BN
add(bn1,bn2)
  	OpenSSL::BN bn1
  	OpenSSL::BN bn2
    ALIAS:
    	sub = 1
    CODE:
    	RETVAL = BN_new();
        BN_init(RETVAL);
        switch(ix) {
          case 0:
        	BN_add(RETVAL, bn1, bn2);
                break;
          case 1:
                BN_sub(RETVAL, bn1, bn2);
                break;
        }
    OUTPUT:
    	RETVAL
  
OpenSSL::BN
mul(bn1,bn2)
  	OpenSSL::BN bn1
        OpenSSL::BN bn2
    ALIAS:
    	div = 1
        mod = 2
        exp = 3
PREINIT:
        BN_CTX  *ctx;
    CODE:
        ctx = BN_CTX_new();
        BN_CTX_init(ctx);
    	RETVAL = BN_new();
        BN_init(RETVAL);
        switch(ix) {
          case 0:
        	BN_mul(RETVAL, bn1, bn2, ctx);
                break;
          case 1:
                 {
                   BIGNUM *tmp = BN_new();
                   BN_init(tmp);
                   if(BN_is_zero(bn2)) {
                     BN_clear_free(tmp);
                     croak("Illegal division by zero");
                   }
                   BN_div(RETVAL, tmp, bn1, bn2, ctx);
                   BN_clear_free(tmp);
                 }
                break;
          case 2:
                 {
                   BIGNUM *tmp = BN_new();
                   BN_init(tmp);
                   if(BN_is_zero(bn2)) {
                     BN_clear_free(tmp);
                     croak("Illegal modulus zero");
                   }
                   BN_div(tmp, RETVAL, bn1, bn2, ctx);
                   BN_clear_free(tmp);
                 }
                break;
          case 3:
                 {
                   BN_exp(RETVAL, bn1, bn2, ctx);
                 }
                break;
        }
        BN_CTX_free(ctx);
    OUTPUT:
    	RETVAL

IV
icmp(bn1,bn2)
  	OpenSSL::BN bn1
        OpenSSL::BN bn2
    CODE:
	RETVAL = BN_cmp(bn1,bn2);
    OUTPUT:
    	RETVAL
        
void
inc(bn)
  	OpenSSL::BN bn
   ALIAS:
   	dec = 1
   CODE:
   	((ix) ? BN_sub_word : BN_add_word)(bn, 1);
        
    	
SV *
stringify(bn)
  	OpenSSL::BN bn
PREINIT:
    	char *p;
    CODE:
        p = BN_bn2dec(bn);
    	RETVAL = newSVpv(p,0);
        free(p);
    OUTPUT:
    	RETVAL

OpenSSL::BN
lshift(bn,cnt)
  	OpenSSL::BN bn
  	IV cnt
    ALIAS:
    	rshift = 1
    CODE:
    	RETVAL = BN_new();
        BN_init(RETVAL);
        if(ix)
  		BN_rshift(RETVAL,bn,cnt);
        else
        	BN_lshift(RETVAL, bn, cnt);
    OUTPUT:
    	RETVAL

OpenSSL::BN
sqr(bn)
  	OpenSSL::BN bn
PREINIT:
    	BN_CTX *ctx;
   CODE:
        ctx = BN_CTX_new();
        BN_CTX_init(ctx);
    	RETVAL = BN_new();
        BN_init(RETVAL);
        BN_sqr(RETVAL, bn, ctx);
        BN_CTX_free(ctx);
   OUTPUT:
   	RETVAL
   
bool
bnbool(bn)
  	OpenSSL::BN bn
    CODE:
	RETVAL = !BN_is_zero(bn);
    OUTPUT:
    	RETVAL
        
bool
isprime(bn)
  	OpenSSL::BN bn
PREINIT:
   	BN_CTX *ctx;
   CODE:
        ctx = BN_CTX_new();
        BN_CTX_init(ctx);
	RETVAL = BN_is_prime(bn, /*30*/0, 0, ctx, 0);
   OUTPUT:
   	RETVAL
        
        
void
DESTROY(bn)
  	OpenSSL::BN bn
    CODE:
    	BN_clear_free(bn);


    	
