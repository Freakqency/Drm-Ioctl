
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: drm_ioc32.c,v 1.2 2018/08/27 04:58:19 riastradh Exp $");

#include <compat/netbsd32/netbsd32.h>
#include <compat/netbsd32/netbsd32_drm.h>

#include <linux/types.h>
#include <drm/drmP.h>

#define DRM_IOCTL_VERSION32		DRM_IOWR(0x00, drm_version32_t)
#define DRM_IOCTL_GET_UNIQUE32		DRM_IOWR(0x01, drm_unique32_t)
#define DRM_IOCTL_GET_MAP32		DRM_IOWR(0x04, drm_map32_t)
#define DRM_IOCTL_GET_CLIENT32		DRM_IOWR(0x05, drm_client32_t)
#define DRM_IOCTL_GET_STATS32		DRM_IOR( 0x06, drm_stats32_t)

#define DRM_IOCTL_SET_UNIQUE32		DRM_IOW( 0x10, drm_unique32_t)
#define DRM_IOCTL_ADD_MAP32		DRM_IOWR(0x15, drm_map32_t)
#define DRM_IOCTL_ADD_BUFS32		DRM_IOWR(0x16, drm_buf_desc32_t)
#define DRM_IOCTL_MARK_BUFS32		DRM_IOW( 0x17, drm_buf_desc32_t)
#define DRM_IOCTL_INFO_BUFS32		DRM_IOWR(0x18, drm_buf_info32_t)
#define DRM_IOCTL_MAP_BUFS32		DRM_IOWR(0x19, drm_buf_map32_t)
#define DRM_IOCTL_FREE_BUFS32		DRM_IOW( 0x1a, drm_buf_free32_t)

#define DRM_IOCTL_RM_MAP32		DRM_IOW( 0x1b, drm_map32_t)

#define DRM_IOCTL_SET_SAREA_CTX32	DRM_IOW( 0x1c, drm_ctx_priv_map32_t)
#define DRM_IOCTL_GET_SAREA_CTX32	DRM_IOWR(0x1d, drm_ctx_priv_map32_t)

#define DRM_IOCTL_RES_CTX32		DRM_IOWR(0x26, drm_ctx_res32_t)
#define DRM_IOCTL_DMA32			DRM_IOWR(0x29, drm_dma32_t)

#define DRM_IOCTL_AGP_ENABLE32		DRM_IOW( 0x32, drm_agp_mode32_t)
#define DRM_IOCTL_AGP_INFO32		DRM_IOR( 0x33, drm_agp_info32_t)
#define DRM_IOCTL_AGP_ALLOC32		DRM_IOWR(0x34, drm_agp_buffer32_t)
#define DRM_IOCTL_AGP_FREE32		DRM_IOW( 0x35, drm_agp_buffer32_t)
#define DRM_IOCTL_AGP_BIND32		DRM_IOW( 0x36, drm_agp_binding32_t)
#define DRM_IOCTL_AGP_UNBIND32		DRM_IOW( 0x37, drm_agp_binding32_t)

#define DRM_IOCTL_SG_ALLOC32		DRM_IOW( 0x38, drm_scatter_gather32_t)
#define DRM_IOCTL_SG_FREE32		DRM_IOW( 0x39, drm_scatter_gather32_t)

#define DRM_IOCTL_UPDATE_DRAW32		DRM_IOW( 0x3f, drm_update_draw32_t)

#define DRM_IOCTL_WAIT_VBLANK32		DRM_IOWR(0x3a, drm_wait_vblank32_t)

#define DRM_IOCTL_MODE_ADDFB232		DRM_IOWR(0xb8, drm_mode_fb_cmd232_t)

// Compat DRM Version Implementation

typedef struct {
	int version_major;		/**< Major version */
	int version_minor;	  	/**< Minor version */
	int version_patchlevel;	  	/**< Patch level */
	uint32_t name_len;	    	/**< Length of name buffer */
	netbsd32_pointer_t name;  	/**< Name of driver */
	uint32_t date_len;	    	/**< Length of date buffer */
	netbsd32_pointer_t date;  	/**< User-space buffer to hold date */
	uint32_t desc_len;	    	/**< Length of desc buffer */
	netbsd32_pointer_t desc;  	/**< User-space buffer to hold desc */
} drm_version32_t;

static int
compat_drm_version(struct file *file, void *arg)
{

	drm_version32_t v32;
	struct drm_version v64;
	int error;

	if ((error = copyin(&v32, arg, sizeof(v32))) != 0)
		return error;

	v64.name_len = v32.name_len;
	v64.name = (char *)NETBSD32PTR64(v32.name);
	v64.date_len = v32.date_len;
	v64.date = (char *)NETBSD32PTR64(v32.date);
	v64.desc_len = v32.desc_len;
	v64.desc =(char *)NETBSD32PTR64(v32.desc);

	error = drm_ioctl(file, DRM_IOCTL_VERSION, &v64);
	if (error)
		return error;

	v32.version_major = v64.version_major;
	v32.version_minor = v64.version_minor;
	v32.version_patchlevel = v64.version_patchlevel;
	/* strings have already been copied in place */
	v32.name_len = v64.name_len;
	v32.date_len = v64.date_len;
	v32.desc_len = v64.desc_len;

	return copyout(arg, &v32, sizeof(v32));
}

typedef struct drm_unique32 {
        uint32_t unique_len; 
        netbsd32_pointer_t unique;    
} drm_unique32_t;

static int
compat_drm_getunique(struct file *file, void *arg)
{
        drm_unique32_t uq32;
        struct drm_unique uq64;
        int error;

        if ((error = copyin(&uq32, arg, sizeof(uq32))) != 0)
                return error;

	uq64.unique_len = uq32.unique_len;
	uq64.unique = (char *)NETBSD32PTR64(uq32.unique);

        error = drm_ioctl(file, DRM_IOCTL_GET_UNIQUE, &uq64);

        if (error)
                return error;

	//unique should already be copied
	uq32.unique_len = uq64.unique_len;

	if ((error = copyout(arg, &uq32, sizeof(uq32))) != 0)
		return error;

        return 0;
}

static int
compat_drm_setunique(struct file *file, void *arg)
{
        drm_unique32_t uq32;
        struct drm_unique uq64;
	int error;

	if ((error = copyin(&uq32, arg, sizeof(uq32))) != 0)
		return error;

	uq64.unique_len = uq32.unique_len;
	uq64.unique = (char *)NETBSD32PTR64(uq32.unique);

	error = drm_ioctl(file, DRM_IOCTL_SET_UNIQUE, &uq64);
	if (error)
		return error;

	// XXX: do we need copyout and copying the fields here?

        return error;
}

typedef struct drm_map32 {
        uint32_t offset;             /**< Requested physical address (0 for SAREA)*/
        uint32_t size;               /**< Requested physical size (bytes) */
        enum drm_map_type type;      /**< Type of memory to map */
        enum drm_map_flags flags;    /**< Flags */
        netbsd32_pointer_t handle;   /**< User-space: "Handle" to pass to mmap() */
        int mtrr;                    /**< MTRR slot used */
} drm_map32_t;

static void
map32to64(struct drm_map *m64, const drm_map32_t *m32)
{
	m64->offset = m32->offset;
	m64->size = m32->size;
	m64->type = m32->type;
	m64->flags = m32->flags;
	m64->handle = NETBSD32PTR64(m64->handle);
	m64->mtrr = m32->mtrr;
}

static void
map64to32(drm_map32_t *m32, const struct drm_map *m64)
{
	m32->offset = m64->offset;
	m32->size = m64->size;
	m32->type = m64->type;
	m32->flags = m64->flags;
	m32->handle = NETBSD32PTR32(m32->handle);
	m32->mtrr = m64->mtrr;
}

static int
compat_drm_getmap(struct file *file, void *arg)
{
        drm_map32_t m32;
        struct drm_map m64;
        int error;

	if ((error = copyin(&m32, arg, sizeof(m32))) != 0)
		return error;

	map32to64(&m64, &m32);

        error = drm_ioctl(file, DRM_IOCTL_GET_MAP, &m64);
        if (error)
                return error;

	map64to32(&m32, &m64);

	return copyout(arg, &m32, sizeof(m32));
}

static int
compat_drm_addmap(struct file *file, void *arg)
{
	drm_map32_t m32;
	struct drm_map m64;
	int error;

	if ((error = copyin(&m32, arg, sizeof(m32))) != 0)
		return error;

	map32to64(&m64, &m32);

	error = drm_ioctl(file, DRM_IOCTL_ADD_MAP, &m64);
	if (error)
		return error;
	
	map64to32(&m32, &m64);

#ifdef notyet
	if (m32.handle != (unsigned long)handle)
		printk_ratelimited(KERN_ERR "compat_drm_addmap truncated handle"
				   " %p for type %d offset %x\n",
				   handle, m32.type, m32.offset);
#endif

	return copyout(arg, &m32, sizeof(m32));
}


static int
compat_drm_rmmap(struct file *file, void *arg)
{
	drm_map32_t m32;
	struct drm_map m64;
	int error;
	if ((error = copyin(&m32, arg, sizeof(m32))) != 0)
		return error;

	map32to64(&m64, &m32);

	error = drm_ioctl(file, DRM_IOCTL_RM_MAP, &m64);
	if (error)
		return error;
	
	map64to32(&m32, &m64);

	return copyout(arg, &m32, sizeof(m32));
}

typedef struct drm_client32 {
	int idx;	/**< Which client desired? */
	int auth;	/**< Is client authenticated? */
	uint32_t pid;	/**< Process ID */
	uint32_t uid;	/**< User ID */
	uint32_t magic;	/**< Magic */
	uint32_t iocs;	/**< Ioctl count */
} drm_client32_t;

static void
client32to64(struct drm_client *c64, const drm_client32_t *c32)
{
	c64->idx = c32->idx;
	c64->auth = c32->auth;
	c64->pid = c32->pid;
	c64->uid = c32->uid;
	c64->iocs = c64->iocs;
}

static void 
client64to32(drm_client32_t *c32, const drm_client *c64)
{
	c32->idx = c64->idx;
	c32->auth = c64->auth;
	c32->pid = c64->pid;
	c32->uid = c64->uid;
	c32->iocs = c64->iocs;
}
static int 
compat_drm_getclient(struct file *file, void *arg)
{
	drm_client32_t c32;
	struct drm_client c64;
	int error;
	
	if ((error = copyin(&c32, arg, sizeof(c32))) != 0)
		return error;

	client32to64(&c64, &c32);

	error = drm_ioctl(file, DRM_IOCTL_GET_CLIENT, &c64);

	if (error)
		return error;

	client64to32(&c32, &c64);

	return copyout(arg, &c32, sizeof(c32));
}

typedef struct drm_stats32 {
	uint32_t count;
	struct {
		uint32_t value;
		enum drm_stat_type type;
	} data[15];
} drm_stats32_t;

static int 
compat_drm_getstats(struct file *file, void *arg)
{
	drm_stats32_t s32;
	struct drm_stats s64;
	int error;

	if ((error = copyin(&s32, arg, sizeof(s32))) !=0)
		return error;

	s64.count = s32.count;

	error = drm_ioctl(file, DRM_IOCTL_GET_STATS, &s64);

	if (error)
		return error;

	for (int i=0; i < 15; ++i) {
		s64.data[i].value=s32.data[i].value;
		s64.data[i].type=s32.data[i].type;
	}

	return copyout(arg, &s32, sizeof(s32));
}

typedef struct drm_buf_desc32 {
	int count;		 /**< Number of buffers of this size */
	int size;		 /**< Size in bytes */
	int low_mark;		 /**< Low water mark */
	int high_mark;		 /**< High water mark */
	int flags;
	uint32_t agp_start;		 /**< Start address in the AGP aperture */
} drm_buf_desc32_t;

static int 
compat_drm_addbufs(struct file *file, void *arg)
{
	struct drm_buf_desc buf64;
	int error;
	unsigned long agp_start;

	if (!buf || (error = !access_ok(VERIFY_WRITE, arg, sizeof(arg)) !=0))
		return error;

	if ((error = copyin(&buf64, arg, offsetof(drm_buf_desc32_t, agp_start))) !=0)
		return error;

	arg->agp_start=agp_start;
	agp_start = buf64.agp_start;

	error = drm_ioctl(file, DRM_IOCTL_ADD_BUFS, &buf64);

	if (error)
		return error;

	if ((error = copyin(&arg, buf64, offsetof(drm_buf_desc32_t, agp_start))) !=0)
		return error;

	buf64.agp_start = agp-start;
	agp_start = arg->agp_start;

	return 0;
}

static int 
compat_drm_markbufs(struct file *file, void *arg)
{
	drm_buf_desc32_t b32;
	struct drm_buf_desc buf64;

	if ((error = copyin(&b32, arg, sizeof(b32) )) !=0)
		return error;

	b32.size = b64.size;
	b32.low_mark = b64.low_mark;
	b32.high_mark = b64.high_mark; 

	return drm_ioctl(file, DRM_IOCTL_MARK_BUFS, &buf64);
}

int
netbsd32_drm_ioctl(struct file *file, unsigned long cmd, void *arg,
    struct lwp *l)
{
	switch (cmd) {
	case DRM_IOCTL_VERSION32:
		return compat_drm_version(file, arg);
	case DRM_IOCTL_GET_UNIQUE32:
		return compat_drm_getunique(file,arg);
	case DRM_IOCTL_SET_UNIQUE32:
		return compat_drm_setunique(file,arg);
	default:
		return EINVAL;
	}
}
