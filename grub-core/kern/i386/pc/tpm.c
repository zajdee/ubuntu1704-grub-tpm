#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/sha1.h>
#include <grub/misc.h>
#include <grub/i386/pc/int.h>

#define TCPA_MAGIC 0x41504354

static int tpm_presence = -1;

int tpm_present(void);

int tpm_present(void)
{
  struct grub_bios_int_registers regs;

  if (tpm_presence != -1)
    return tpm_presence;

  regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
  regs.eax = 0xbb00;
  regs.ebx = TCPA_MAGIC;
  grub_bios_interrupt (0x1a, &regs);

  if (regs.eax == 0)
    tpm_presence = 1;
  else
    tpm_presence = 0;

  return tpm_presence;
}

grub_err_t
grub_tpm_execute(PassThroughToTPM_InputParamBlock *inbuf,
		 PassThroughToTPM_OutputParamBlock *outbuf)
{
  struct grub_bios_int_registers regs;
  grub_addr_t inaddr, outaddr;

  if (!tpm_present())
    return 0;

  inaddr = (grub_addr_t) inbuf;
  outaddr = (grub_addr_t) outbuf;
  regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
  regs.eax = 0xbb02;
  regs.ebx = TCPA_MAGIC;
  regs.ecx = 0;
  regs.edx = 0;
  regs.es = (inaddr & 0xffff0000) >> 4;
  regs.edi = inaddr & 0xffff;
  regs.ds = outaddr >> 4;
  regs.esi = outaddr & 0xf;

  grub_bios_interrupt (0x1a, &regs);

  if (regs.eax)
    {
	tpm_presence = 0;
	return grub_error (GRUB_ERR_IO, N_("TPM error %x, disabling TPM"), regs.eax);
    }

  return 0;
}

typedef struct {
	grub_uint32_t pcrindex;
	grub_uint32_t eventtype;
	grub_uint8_t digest[20];
	grub_uint32_t eventdatasize;
	grub_uint8_t event[0];
} GRUB_PACKED Event;

typedef struct {
	grub_uint16_t ipblength;
	grub_uint16_t reserved;
	grub_uint32_t hashdataptr;
	grub_uint32_t hashdatalen;
	grub_uint32_t pcr;
	grub_uint32_t reserved2;
	grub_uint32_t logdataptr;
	grub_uint32_t logdatalen;
} GRUB_PACKED EventIncoming;

typedef struct {
	grub_uint16_t opblength;
	grub_uint16_t reserved;
	grub_uint32_t eventnum;
	grub_uint8_t  hashvalue[20];
} GRUB_PACKED EventOutgoing;

grub_err_t
grub_tpm_log_event(unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		   const char *description)
{
	struct grub_bios_int_registers regs;
	EventIncoming incoming;
	EventOutgoing outgoing;
	Event *event;
	grub_uint32_t datalength;

	if (!tpm_present())
		return 0;

	datalength = grub_strlen(description);
	event = grub_zalloc(datalength + sizeof(Event));
	if (!event)
		return grub_error (GRUB_ERR_OUT_OF_MEMORY,
				   N_("cannot allocate TPM event buffer"));

	/* hash buffer */
	grub_uint32_t result[5] = { 0 };
	grub_err_t err = sha1_hash_buffer(buf, size, result);

	if (err != GRUB_ERR_NONE) {
		grub_fatal("grub_tpm_log_event: sha1_hash_buffer failed.");
	}

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE] = { 0 };
	int j, i = 0;
	for (j = 0; j < 5; j++) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

	event->pcrindex = pcr;
	event->eventtype = 0x0d;
	event->eventdatasize = grub_strlen(description);
	grub_memcpy(event->event, description, datalength);
	grub_memcpy(event->digest, &convertedResult, SHA1_DIGEST_SIZE);

	incoming.ipblength = sizeof(incoming);
	incoming.hashdataptr = (grub_uint32_t)0;
	incoming.hashdatalen = 0;
	incoming.pcr = pcr;
	incoming.logdataptr = (grub_uint32_t)event;
	incoming.logdatalen = datalength + sizeof(Event);

	regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
	regs.eax = 0xbb01;
	regs.ebx = TCPA_MAGIC;
	regs.ecx = 0;
	regs.edx = 0;
	regs.es = (((grub_addr_t) &incoming) & 0xffff0000) >> 4;
	regs.edi = ((grub_addr_t) &incoming) & 0xffff;
	regs.ds = (((grub_addr_t) &outgoing) & 0xffff0000) >> 4;
	regs.esi = ((grub_addr_t) &outgoing) & 0xffff;

	grub_bios_interrupt (0x1a, &regs);

	grub_free(event);

	if (regs.eax)
	  {
		tpm_presence = 0;
		return grub_error (GRUB_ERR_IO, N_("TPM error %x, disabling TPM"), regs.eax);
	  }

	return 0;
}
