###########################################################################
# Kbuild fragment for nvidia-vgpu-vfio.ko
###########################################################################

NV_VGPU_VFIO_BUILD_TYPE = release

#
# Define NVIDIA_VGPU_VFIO_{SOURCES,OBJECTS}
#

include $(src)/nvidia-vgpu-vfio/nvidia-vgpu-vfio-sources.Kbuild

NVIDIA_VGPU_VFIO_OBJECTS = $(patsubst %.c,%.o,$(NVIDIA_VGPU_VFIO_SOURCES))

obj-m += nvidia-vgpu-vfio.o
nvidia-vgpu-vfio-y := $(NVIDIA_VGPU_VFIO_OBJECTS)

NVIDIA_VGPU_VFIO_KO = nvidia-vgpu-vfio/nvidia-vgpu-vfio.ko

NV_KERNEL_MODULE_TARGETS += $(NVIDIA_VGPU_VFIO_KO)

#
# Define nvidia-vgpu-vfio.ko specific CFLAGS.
#

NVIDIA_VGPU_VFIO_CFLAGS += -I$(src)/nvidia-vgpu-vfio
NVIDIA_VGPU_VFIO_CFLAGS += -DNV_BUILD_MODULE_INSTANCES=0
NVIDIA_VGPU_VFIO_CFLAGS += -DNVIDIA_UNDEF_LEGACY_BIT_MACROS

NV_KVM_MIGRATION_UAPI ?= 0
ifneq ($(NV_KVM_MIGRATION_UAPI),0)
  NVIDIA_VGPU_VFIO_CFLAGS += -DNV_KVM_MIGRATION_UAPI
endif

ifneq ($(NV_VGPU_VFIO_BUILD_TYPE),release)
  NVIDIA_VGPU_VFIO_CFLAGS += -DDEBUG
endif

$(call ASSIGN_PER_OBJ_CFLAGS, $(NVIDIA_VGPU_VFIO_OBJECTS), $(NVIDIA_VGPU_VFIO_CFLAGS))

#
# Register the conftests needed by nvidia-vgpu-vfio.ko
#

NV_OBJECTS_DEPEND_ON_CONFTEST += $(NVIDIA_VGPU_VFIO_OBJECTS)

NV_CONFTEST_GENERIC_COMPILE_TESTS  += nvidia_vgpu_kvm_build
NV_CONFTEST_FUNCTION_COMPILE_TESTS += vfio_register_notifier
NV_CONFTEST_FUNCTION_COMPILE_TESTS += mdev_parent_dev
NV_CONFTEST_FUNCTION_COMPILE_TESTS += mdev_dev
NV_CONFTEST_FUNCTION_COMPILE_TESTS += mdev_uuid
NV_CONFTEST_FUNCTION_COMPILE_TESTS += mdev_from_dev
NV_CONFTEST_FUNCTION_COMPILE_TESTS += sg_alloc_table
NV_CONFTEST_FUNCTION_COMPILE_TESTS += vmf_insert_pfn
NV_CONFTEST_FUNCTION_COMPILE_TESTS += mdev_set_iommu_device
NV_CONFTEST_FUNCTION_COMPILE_TESTS += pci_irq_vector_helpers
NV_CONFTEST_FUNCTION_COMPILE_TESTS += kvmalloc
NV_CONFTEST_FUNCTION_COMPILE_TESTS += pgprot_decrypted
NV_CONFTEST_TYPE_COMPILE_TESTS     += vm_fault_has_address
NV_CONFTEST_TYPE_COMPILE_TESTS     += mdev_parent
NV_CONFTEST_TYPE_COMPILE_TESTS     += vm_ops_fault_removed_vma_arg
NV_CONFTEST_TYPE_COMPILE_TESTS     += vfio_info_add_capability_has_cap_type_id_arg
NV_CONFTEST_TYPE_COMPILE_TESTS     += vfio_device_gfx_plane_info
NV_CONFTEST_TYPE_COMPILE_TESTS     += vfio_device_migration_info
NV_CONFTEST_TYPE_COMPILE_TESTS     += vm_fault_t
NV_CONFTEST_TYPE_COMPILE_TESTS     += vfio_device_migration_has_start_pfn
NV_CONFTEST_TYPE_COMPILE_TESTS     += vmalloc_has_pgprot_t_arg
