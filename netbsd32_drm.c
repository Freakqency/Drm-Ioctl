
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
	v64.name = NETBSD32PTR64(v32.name);
	v64.date_len = v32.date_len;
	v64.date = NETBSD32PTR64(v32.date);
	v64.desc_len = v32.desc_len;
	v64.desc = NETBSD32PTR64(v32.desc);

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
	uq32.unique_len = uq64.unique_len;
	uq32.unique = NETBSD32PTR64(uq64.unique);

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

	if ((error = copyin(&s32, arg, sizeof(s32))) != 0)
		return error;

	s64.count = s32.count;

	error = drm_ioctl(file, DRM_IOCTL_GET_STATS, &s64);
	if (error)
		return error;

	// XXX: or does that need to be count?
	for (int i = 0; i < __arraycount(s64.data); ++i) {
		s64.data[i].value = s32.data[i].value;
		s64.data[i].type = s32.data[i].type;
	}

	return copyout(arg, &s32, sizeof(s32));
}

typedef struct drm_buf_desc32 {
	int count;		 /**< Number of buffers of this size */
	int size;		 /**< Size in bytes */
	int low_mark;		 /**< Low water mark */
	int high_mark;		 /**< High water mark */
	int flags;
	netbsd_pointer_t agp_start;
				/**< Start address in the AGP aperture */
} drm_buf_desc32_t;

static int 
compat_drm_addbufs(struct file *file, void *arg)
{
	drm_buf_desc32_t buf32;
	struct drm_buf_desc buf64;
	int error;

	if ((error = copyin(&buf32, arg, sizeof(buf32))) != 0)
		return error;
#ifdef notyet
	// XXX: that will not compile? what is buf?
	if (!buf64 || (error = !access_ok(VERIFY_WRITE, arg, sizeof(arg)) != 0))
		return error;
#endif

	// XXX: assign 32->64

	error = drm_ioctl(file, DRM_IOCTL_ADD_BUFS, &buf64);
	if (error)
		return error;

	// XXX assign 64->32

	if ((error = copyout(&buf32, arg, sizeofs(buf32))) != 0)
		return error;

	buf64.agp_start = agp_start;
	agp_start = arg.agp_start;

	return 0;
}

static int 
compat_drm_markbufs(struct file *file, void *arg)
{
	drm_buf_desc32_t b32;
	struct drm_buf_desc buf64;

	if ((error = copyin(&b32, arg, sizeof(b32))) != 0)
		return error;

	b64.size = b32.size;
	b64.low_mark = b32.low_mark;
	b64.high_mark = b32.high_mark; 
	//XXX: more stuff?

	return drm_ioctl(file, DRM_IOCTL_MARK_BUFS, &buf64);
}

typedef struct drm_buf_info32 {
	int count;		/**< Entries in list */
	netbsd32_pointer_t list;
} drm_buf_info32_t;

static int 
compat_drm_infobufs(struct file *file, void *arg)
{
	drm_buf_info32_t req32;
	drm_buf_desc32_t *to;
	struct drm_buf_info req64;
	struct drm_buf_desc list64;
	size_t nbytes;
	int error;
	int count, actual;

	if ((error = copyin(&req32, arg, sizeof(req32))) != 0)
		return error;

	count = req32.count;
	to = NETBSD32PTR32(req32.list);

	if (count < 0)
		count = 0;

#ifdef notyet
	if (count > 0
	    && ( error = !access_ok(VERIFY_WRITE, to, count * sizeof(drm_buf_desc32_t))) != 0)
		return error;
#endif

	nbytes = sizeof(req64) + count * sizeof(list64);
	// XXX: How to handle these type casts?
	//list = (struct drm_buf_desc *) (req64 + 1);
	list64 = (struct drm_buf_desc *) (req64 + 1);
	count = req64.count;
	list64 = NETBSD32PTR64(req64.list);

	error = drm_ioctl(file, DRM_IOCTL_INFO_BUFS, &req64);
	if (error)
		return error;


	req64.count = actual;

	if (count >= actual)
		for (int i = 0; i < actual; ++i)
			if ((error = copyin(&to[i], &list64[i], offset(struct drm_buf_desc, flags))) != 0)
				return error;

	acutal = arg.count;

	return 0;
}

typedef struct drm_buf_pub32 {
	int idx;		/**< Index into the master buffer list */
	int total;		/**< Buffer size */
	int used;		/**< Amount of buffer in use (for DMA) */
	uint32_t address;	/**< Address of buffer */
} drm_buf_pub32_t;

typedef struct drm_buf_map32 {
	int count;		/**< Length of the buffer list */
	uint32_t virtual;	/**< Mmap'd area in user-virtual */
	netbsd32_pointer_t list;		/**< Buffer information */
} drm_buf_map32_t;

static int 
compat_drm_mapbufs(struct file *file, void *arg)
{
	drm_buf_map32_t req32;
	//drm_buf_pub32_t __user *list32;
	drm_buf_pub32_t list32;
	struct drm_buf_map req64;
	//struct drm_buf_pub __user *list;
	struct drm_buf_pub list64;
	int error;
	int count, actual;
	size_t nbytes;
	void addr;

	if ((error = copyin(&req32, arg, sizeof(req32))) != 0)
		return error;

	count = req32.count;
	// XXX:Same type cast
	//list32 = (void __user *)(unsigned long)req32.list;
	list32 = NETBSD32PTR64(req32.list);
	nbytes = sizeof(req64) + count * sizeof(struct drm_buf_pub);
	// XXX:Same type cast
	//list = (struct drm_buf_pub *) (req64 + 1);
	list64 = (struct drm_buf_pub *) (req64 + 1);
	count = req64.count;
	list64 = NETBDS32PTR64(req64.list);

	error = drm_ioctl(file, DRM_IOCTL_MAP_BUFS, &req64);
	if (error)
		return error;

	req64.count = actual;

	if (count >= actual)
		for (int i=0; i < actual; ++i){
			if ((error = copyin(&list32[i], &list64[i], offsetof(struct drm_buf_pub, address))) != 0)
				return error;
			list64[i].address = addr;
			addr = list32[i].address;
		}

	actual = arg.count;
	req64.virtual = addr;
	addr = arg.virtual;

	return 0;
}

typedef struct drm_buf_free32 {
	int count;
	netbsd32_pointer_t list;
} drm_buf_free32_t;

static int 
compat_drm_freebufs(struct file *file, void *arg)
{
	drm_buf_free32_t req32;
	struct drm_buf_free req64;
	
	if ((error = copyin(&req32, arg, sizeof(req32))) != 0)
		return error;

	req32.count = req64.count;
	req32.list = (char *)NETBSD32PTR64(req64.list);

	return drm_ioctl(file, DRM_IOCTL_FREE_BUFS, &req64);
}

typedef struct drm_ctx_priv_map32 {
	unsigned int ctx_id;	         /**< Context requesting private mapping */
	netbsd32_pointer_t handle;	 /**< Handle of map */
} drm_ctx_priv_map32_t;

static int 
compat_drm_setsareactx(struct file *file, void *arg)
{
	drm_ctx_priv_map32_t req32;
	struct drm_ctx_pric_map req64;

	if ((error = copyin(&req32, arg, sizeof(req32))) != 0)
		return error;

	req32.ctx_id = req64.ctx_id;
	req32.handle = NETBSD32PTR64(req64.handle);

	return drm_ioctl(file, DRM_IOCTL_SET_SAREA_CTX, &req64);
}

static int 
compat_drm_getsareactx(struct file *file, void *arg)
{
	struct drm_ctx_priv_map req64;
	int error;
	unsigned int ctx_id;
	void handle;

	if ((error = access_ok(VERIFY_WRITE, arg, sizeof(arg))) != 0)
		return error;

	arg.ctx_id = ctx_id;
	ctx_id = req64.ctx_id;

	error = drm_ioctl(file, DRM_IOCTL_GET_SAREA_CTX, &req64);
	if (error)
		return error;

	req64.handle = handle;
	handle = NETBSD32PTR64(arg.handle);

	return 0;
}

typedef struct drm_ctx_res32 {
	int count;
	netbsd32_pointer_t contexts;
} drm_ctx_res32_t;

static int 
compat_drm_resctx(struct file *file, void *arg)
{
	drm_ctx_res32_t res32;
	struct drm_ctx_res res64;
	int error;

	if ((error = copyin(&res32, arg, sizeof(res32))) != 0)
		return error;

	res32.count = res64.count;
	res32.contexts = (char *)NETBSD32PTR64(res64.contexts);

	error = drm_ioctl(file, DRM_IOCTL_RES_CTX, &res64);
	if (error)
		return error;

	res64.count = res32.count;
	res32.count = arg.count;

	return 0;
}

typedef struct drm_dma32 {
	int context;		  		  /**< Context handle */
	int send_count;		  		  /**< Number of buffers to send */
	netbsd32_pointer_t send_indices;	  /**< List of handles to buffers */
	netbsd32_pointer_t send_sizes;		  /**< Lengths of data to send */
	enum drm_dma_flags flags;		  /**< Flags */
	netbsd32_pointer_t request_count;	  /**< Number of buffers requested */
	int request_size;	 		   /**< Desired size for buffers */
	netbsd32_pointer_t request_indices;	  /**< Buffer information */
	netbsd32_pointer_t request_sizes;
	int granted_count;	                  /**< Number of buffers granted */
} drm_dma32_t
;
static void 
dma64to32(drm_dma32_t *d32, const struct drm_dma *d64)
{
	d32->send_count = d64->send_count;
	d32->send_indices = NETBSD32PTR64(d64->send_indices);
	d32->send_sizes = NETBSD32PTR64(d64->send_sizes);
	d32->flags = d64->flags;
	d32->request_count = d64->request_count;
	d32->request_indices = NETBSD32PTR64(d64->request_indices);
	d32->request_sizes = NETBSD32PTR64(d64->request_sizes);
}

static void 
dma32to64(struct drm_dma *d64, const drm_dma32_t *d32)
{
	d64->request_size = d32->request.size;
	d64->grandted_count = d32->granted_count;
}

static int 
compat_drm_dma(struct file *file, void *arg)
{
	drm_dma32_t d32;
	struct drm_dma d64;
	int error;

	if ((error = copyin(&d32, arg, sizeof(d32))) != 0)
		return error;

	dma64to32(&d32, &d64);

	error = drm_ioctl(file, DRM_IOCTL_DMA, &d64);
	if (error)
		return error;

	dma32to64(&d64, &d32);
	d32.request_size = arg.request_size;
	d32.granted_count = arg.granted_count;

	return 0;
}


#if IS_ENABLED(CONFIG_AGP)
typedef struct drm_agp_mode32 {
	uint32_t mode;	/**< AGP mode */
} drm_agp_mode32_t;

static int 
compat_drm_agp_enable(struct file *file, void *arg)
{
	drm_agp_mode32_t m32;
	struct drm_agp_mode m64;
	
	if ((error = copyin(&m32, arg, sizeof(m32))) != 0)
		return error;

	arg.mode = m32.mode;
	m32.mode = m64.mode;

	return drm_ioctl(file, DRM_IOCTL_AGP_ENABLE, &m64);
}

typedef struct drm_agp_info32 {
	int agp_version_major;
	int agp_version_minor;
	uint32_t mode;
	uint32_t aperture_base;		/* physical address */
	uint32_t aperture_size;		/* bytes */
	uint32_t memory_allowed;	/* bytes */
	uint32_t memory_used;

	/* PCI information */
	unsigned short id_vendor;
	unsigned short id_device;
} drm_agp_info32_t;

static void 
info32to64(struct drm_agp_info *i64, const drm_agp_info32_t *i32)
{
	i64->agp_version_major = i32->agp_version_major;
	i64->agp_version_minor = i32->agp_vrsion_minor;
	i64->mode = i32->mode;
	i64->aperture_base = i32->aperture_base;
	i64->aperture_size = i32->aperture_size;
	i64->memory_allowed = i32->memory_allowed;
	i64->memory_used = i64->memory_used;
	i64->id_vendor = i32->id_vendor;
	i64->id_device = i32->id_device;
}

static int compat_drm_agp_info(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	drm_agp_info32_t i32;
	struct drm_agp_info i64;
	int error;

	error = drm_ioctl(file, DRM_IOCTL_AGP_INFO, &i64);
	if (error)
		return error;
	
	info32to64(&i64,&i32);
	
	return copyout(arg,&i32,sizeof(i32))

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
