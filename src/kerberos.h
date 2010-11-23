#ifndef VB_KERBEROS_H
# define VB_KERBEROS_H

/* /!\ THIS HEADER IS PRIVATE /!\ */

# ifdef __cplusplus
extern "C" {
# endif

   struct vb_krb5;
   typedef char * (*get_password_f)(void * data);

   struct vb_krb5 * vbkrb5_alloc(void);
   char *vbkrb5_simple_password_cb(void *data);
   void vbkrb5_set_password(struct vb_krb5 *thiz,
                          char *(get_password)(void *data),
                          void * data);

   void vbkrb5_set_login(struct vb_krb5 *thiz, const char *);
   void vbkrb5_set_service(struct vb_krb5 *thiz, const char *);
   void vbkrb5_set_realm(struct vb_krb5 *thiz, const char *);
   const char * vbkrb5_get_otoken_value(struct vb_krb5 *thiz);
   unsigned vbkrb5_get_otoken_len(struct vb_krb5 *thiz);
    const char *vbkrb5_get_otoken_base64(struct vb_krb5 *thiz);
   int vbkrb5_init(struct vb_krb5 *thiz);
   int vbkrb5_import_name(struct vb_krb5 *thiz);
   void vbkrb5_init_context(struct vb_krb5 *thiz);
   void vbkrb5_display_status(struct vb_krb5 *thiz);
   int vbkrb5_check_tokens(struct vb_krb5 *thiz);
   void vbkrb5_clear(struct vb_krb5 *thiz);
   const char *vbkrb5_mech_error(struct vb_krb5 *thiz);
   const char *vbkrb5_gss_error(struct vb_krb5 *thiz);
   const char *vbkrb5_error(int err);
   int vbkrb5_errno(struct vb_krb5 *thiz);
# ifdef __cplusplus
}
# endif

#endif
