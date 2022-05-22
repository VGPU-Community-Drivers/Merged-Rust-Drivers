# Merged-Rust-Drivers
This repository serves as a collection for community made tools that can unlock vGPU technology on consumer Nvidia GPUs.

## Information
Currently the vgpu discord/libvf.io is working on a 510 merged driver there is an aur solution working and usavle the run is still in progress
More info in these discord servers.

Note: I am not the creator of any of these scripts/tools, all credit goes to their original creator. (Should they wish to be credited)

# DISCLAIMER #
Driver is made from nvidia! For Business use Please Contact [Nvidia](https://www.nvidia.com/en-us/data-center/virtual-solutions/) or a Solutions provider: 

This Driver is only for personal use on consumer Hardware with GUI/Frontend attached! 

*Community Edition* / Supported
This is just a store to open it up and *open source our community changes*

### Install
```
wget https://github.com/VGPU-Community-Drivers/Merged-Rust-Drivers/raw/main/NVIDIA-Linux-x86_64-460.73.01-grid-vgpu-kvm.run
chmod +x NVIDIA-Linux-x86_64-460.73.01-grid-vgpu-kvm.run
sudo ./NVIDIA-Linux-x86_64-460.73.01-grid-vgpu-kvm.run
```

### Clone
```
sudo pacman -S git-lfs || sudo apt install git-lfs
git lfs clone https://github.com/VGPU-Community-Drivers/Merged-Rust-Drivers
cd Merged-Rust-Drivers
./repack.sh
sudo ./NVIDIA-Linux-x86_64-460.73.01-grid-vgpu-kvm.run
```
update repo with:
```
git lfs pull && git pull
```

## More Information in:
- [New Wiki](https://krutavshah.github.io/GPU_Virtualization-Wiki/)
- [Google Wiki Doc](https://docs.google.com/document/d/1pzrWJ9h-zANCtyqRgS7Vzla0Y8Ea2-5z2HEi4X75d2Q/edit?usp=sharing)
- [openmdev.io](https://openmdev.io/index.php/Main_Page)


## Credits
- Original Creator of vGPU_unlock: [OG vgpu_unlock DualCoder](https://github.com/DualCoder/vgpu_unlock)
- The creator of vGPU in Rust: [Mbilker Rust-Version](https://github.com/mbilker/vgpu_unlock-rs)
- The creator of the original merged driver: [NVIDIA-Linux-x86_64-460.73.01-grid-vgpu-kvm-v5](https://drive.google.com/file/d/1dCyUteA2MqJaemRKqqTu5oed5mINu9Bw/view)
- and the creator of the DKMS patch system: [vGPU for arch package nvidia-merged-arch](https://github.com/erin-allison/nvidia-merged-arch) 
