#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.
set -o pipefail # Return value of a pipeline is the value of the last command to exit with a non-zero status, or zero if all commands in the pipeline exit successfully.

#try to backup the script
script_path="$(readlink -f "$0")"
echo "Full path: $script_path"
script_name="$(basename "$script_path")"
echo "Filename only: $script_name"
timestamp=$(date +"%Y%m%d_%H%M%S")
# Insert timestamp before last dot (.)
extension="${script_name##*.}"
base="${script_name%.*}"

# Handle scripts without a dot in the name
if [[ "$base" == "$script_name" ]]; then
    backup_name="${script_name}_${timestamp}"
else
    backup_name="${base}_${timestamp}.${extension}"
fi
backup_dir="./backups"
mkdir -p "$backup_dir"

# Copy script
cp "$script_path" "$backup_dir/$backup_name"

echo "Backup created: $backup_dir/$backup_name"

# --- Configuration Variables ---
UBUNTU_RELEASE="22.04.5" # 22.04.5 or 24.04.2
CODE_NAME="jammy" # noble for 24.04.x, jammy for 22.04.x
ARCH="arm64"

# Define a temporary directory for image operations
#TEMP_DIR="/tmp" # Or choose another suitable temporary location if /tmp is too small
TEMP_DIR="/mnt/Data/OS/Linux/RPi/ubuntu"

# Define the base server image URL (adjust if needed for specific releases)
# This URL is for the official Ubuntu Server for Raspberry Pi.
# Always check the latest releases on https://ubuntu.com/download/raspberry-pi
IMAGE_TYPE="desktop" # server or desktop
BASE_IMAGE_URL="https://cdimage.ubuntu.com/releases/${UBUNTU_RELEASE}/release/ubuntu-${UBUNTU_RELEASE}-preinstalled-${IMAGE_TYPE}-${ARCH}+raspi.img.xz"
#BASE_IMAGE_NAME="ubuntu-${UBUNTU_RELEASE}-preinstalled-${IMAGE_TYPE}-${ARCH}+raspi.img.xz"
#DECOMPRESSED_IMAGE_NAME="/tmp/ubuntu-${UBUNTU_RELEASE}-preinstalled-${IMAGE_TYPE}-${ARCH}+raspi.img"
BASE_IMAGE_NAME="${TEMP_DIR}/ubuntu-${UBUNTU_RELEASE}-preinstalled-${IMAGE_TYPE}-${ARCH}+raspi.img.xz"
#DECOMPRESSED_IMAGE_NAME="${TEMP_DIR}/ubuntu-${UBUNTU_RELEASE}-preinstalled-${IMAGE_TYPE}-${ARCH}+raspi.img"
DECOMPRESSED_IMAGE_NAME="/tmp/ubuntu-${UBUNTU_RELEASE}-preinstalled-${IMAGE_TYPE}-${ARCH}+raspi.img"
echo -ne "\033]0;BASE_IMAGE_NAME=${BASE_IMAGE_NAME}\007"

# Output image name
OUTPUT_IMAGE_NAME="${DECOMPRESSED_IMAGE_NAME%.img}-updated.img"
echo "OUTPUT_IMAGE_NAME: ${OUTPUT_IMAGE_NAME}"
#read -p "Press Enter to continue..." # Replaced 'pause' with 'read -p'
COMPRESSED_OUTPUT_IMAGE_NAME="${OUTPUT_IMAGE_NAME}.xz" # New variable for compressed output

# Mount points for the image partitions
BOOT_MOUNT_POINT="/mnt/pi_boot-${CODE_NAME}"
ROOT_MOUNT_POINT="/mnt/pi_root-${CODE_NAME}"

# Variables to store loop device names, initialized to empty
LOOP_DEVICE_FOR_PARTED=""
MAIN_LOOP_DEVICE=""

# --- Functions ---

# Function to display error messages and exit
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait for a loop device to detach
wait_for_device_detach() {
    local dev="$1"
    local max_attempts=30 # Increased attempts for more robustness
    local attempt=0
    echo "Waiting for loop device ${dev} to detach completely..."
    while sudo losetup -a | grep -q "$dev" && [ $attempt -lt $max_attempts ]; do
        echo "  Still active: ${dev} (attempt $((attempt + 1))/${max_attempts})..."
        sleep 10 # Increased sleep duration to 10 seconds
        sudo udevadm settle # Ensure all udev events are processed
        attempt=$((attempt + 1))
    done
    if sudo losetup -a | grep -q "$dev"; then
        error_exit "Loop device ${dev} did not detach after $max_attempts attempts. Manual intervention may be required."
    fi
    echo "Loop device ${dev} successfully detached."
}


# Cleanup function to unmount and detach loop devices
cleanup() {
    echo "--- Running cleanup function ---"

    # Unmount bind mounts first (most specific to least specific)
    # Ensure all bind mounts are safely unmounted
    echo "--- Unmounting bind mounts ---"
    BIND_MOUNTS=("run" "proc" "sys" "dev")
    for dir in "${BIND_MOUNTS[@]}"; do
        mp="$ROOT_MOUNT_POINT/$dir"
        if mountpoint -q "$mp"; then
            echo "Unmounting $mp..."
            sudo umount "$mp" || echo "Warning: Failed to unmount $mp"
        fi
    done

    # Unmount main partitions
    echo "--- Unmounting root and boot partitions ---"
    if mountpoint -q "$BOOT_MOUNT_POINT"; then
        echo "Unmounting $BOOT_MOUNT_POINT..."
        sudo umount "$BOOT_MOUNT_POINT" || echo "Warning: Failed to unmount $BOOT_MOUNT_POINT."
    fi
    # The root mount point unmount is handled more robustly in the main script flow (section 6),
    # but a lazy unmount is a good fallback here in case of script interruption
    if mountpoint -q "$ROOT_MOUNT_POINT"; then
        echo "Unmounting $ROOT_MOUNT_POINT (via cleanup lazy unmount)..."
        sudo umount -l "$ROOT_MOUNT_POINT" || echo "Warning: Failed to lazy unmount $ROOT_MOUNT_POINT during cleanup."
    fi
    
    # Detach loop devices
    if [ -n "$MAIN_LOOP_DEVICE" ] && sudo losetup -a | grep -q "$MAIN_LOOP_DEVICE"; then
        echo "Detaching main loop device ${MAIN_LOOP_DEVICE}..."
        sudo losetup -d "$MAIN_LOOP_DEVICE"
        wait_for_device_detach "$MAIN_LOOP_DEVICE" # Wait for it to fully disappear
    fi
    if [ -n "$LOOP_DEVICE_FOR_PARTED" ] && sudo losetup -a | grep -q "$LOOP_DEVICE_FOR_PARTED"; then
        echo "Detaching partitioning loop device ${LOOP_DEVICE_FOR_PARTED}..."
        sudo losetup -d "$LOOP_DEVICE_FOR_PARTED"
        wait_for_device_detach "$LOOP_DEVICE_FOR_PARTED" # Wait for it to fully disappear
    fi

    # Remove temporary mount directories
    if [ -d "$BOOT_MOUNT_POINT" ]; then
        echo "Removing $BOOT_MOUNT_POINT..."
        rmdir "$BOOT_MOUNT_POINT" 2>/dev/null
    fi
    if [ -d "$ROOT_MOUNT_POINT" ]; then
        echo "Removing $ROOT_MOUNT_POINT..."
        rmdir "$ROOT_MOUNT_POINT" 2>/dev/null
    fi

    # Remove generated image files if they exist (clean up after success or failure)
    # Commenting these out by default in cleanup so that if the script succeeds,
    # the uncompressed image is available for compression and the compressed one is left.
    # If you want to force removal of all generated files on *any* exit, uncomment these.
    # if [ -f "$OUTPUT_IMAGE_NAME" ]; then
    #     echo "Removing $OUTPUT_IMAGE_NAME..."
    #     rm -f "$OUTPUT_IMAGE_NAME"
    # fi
    # if [ -f "$DECOMPRESSED_IMAGE_NAME" ]; then
    #     echo "Removing $DECOMPRESSED_IMAGE_NAME..."
    #     rm -f "$DECOMPRESSED_IMAGE_NAME"
    # fi    
    echo "Cleanup complete."
}

# Register the cleanup function to run on EXIT (normal or error exit)
trap cleanup EXIT

# --- Pre-requisite Checks ---
echo "--- Checking prerequisites ---"

# Check for necessary commands
REQUIRED_COMMANDS=("wget" "xz" "sgdisk" "parted" "losetup" "mount" "umount" "chroot" "rsync" "resize2fs" "udevadm" "e2fsck" "fdisk" "lsof" "fuser")
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command_exists "$cmd"; then
        error_exit "Required command '$cmd' not found. Please install it (e.g., sudo apt install $cmd)."
    fi
done

# Check for qemu-user-static for ARM64 emulation on the host
echo "--- Checking for ARM64 emulation binaries (qemu-user-static) ---"
# This check is only relevant if running on x86_64 host for arm64 target
if [ "$(uname -m)" != "aarch64" ]; then
    EMULATION_OK=true
    # qemu-aarch64-static is the specific binary for ARM64 emulation
    if ! command_exists "qemu-aarch64-static"; then
        echo "Error: Required emulation binary 'qemu-aarch64-static' not found."
        EMULATION_OK=false
    fi

    if [ "$EMULATION_OK" = "false" ]; then
        error_exit "ARM64 emulation binaries (qemu-user-static) are required on your host system (WSL Ubuntu) to chroot into an ARM64 image. Please install them: sudo apt install qemu-user-static binfmt-support"
    fi
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root. Please use 'sudo'."
fi

# Check if apt-cacher-ng is running (optional, but recommended for caching)
echo "--- Checking for apt-cacher-ng service ---"
if ! systemctl is-active --quiet apt-cacher-ng; then
    echo "Warning: apt-cacher-ng service is not running. Package downloads will not be cached."
    echo "To enable caching, install and start apt-cacher-ng on your host system (e.g., sudo apt install apt-cacher-ng && sudo systemctl start apt-cacher-ng)."
    USE_APT_CACHE_NG="false"
else
    echo "apt-cacher-ng service is running. Package downloads will be cached."
    USE_APT_CACHE_NG="true"
fi

# Update CODE_NAME based on UBUNTU_RELEASE
if [ "$UBUNTU_RELEASE" == "22.04.5" ]; then
    CODE_NAME="jammy"
elif [ "$UBUNTU_RELEASE" == "24.04.2" ]; then
    CODE_NAME="noble"
else
    error_exit "Unsupported UBUNTU_RELEASE: ${UBUNTU_RELEASE}. Please add its codename mapping."
fi


# --- Initial Clean up (for previous failed runs) ---
# This section remains for initial state cleanup, but the trap handles mid-script failures.
echo "--- Initial cleanup of previous state (if any) ---"
if mountpoint -q "$BOOT_MOUNT_POINT"; then
    echo "Unmounting $BOOT_MOUNT_POINT..."
    sudo umount "$BOOT_MOUNT_POINT" || echo "Warning: Failed to unmount $BOOT_MOUNT_POINT during initial cleanup. May be already unmounted or busy."
fi
if mountpoint -q "$ROOT_MOUNT_POINT"; then
    echo "Unmounting $ROOT_MOUNT_POINT..."
    sudo umount "$ROOT_MOUNT_POINT" || echo "Warning: Failed to unmount $ROOT_MOUNT_POINT during initial cleanup. May be already unmounted or busy."
fi
rm -rf "$BOOT_MOUNT_POINT" "$ROOT_MOUNT_POINT"
rm -f "$OUTPUT_IMAGE_NAME" # Only remove the final output image, keep the base image for re-runs
rm -f "$COMPRESSED_OUTPUT_IMAGE_NAME" # Also remove compressed output if it exists

# Detach any lingering loop devices from previous runs, if they exist
# This is a more aggressive initial cleanup for losetup devices
echo "Detaching any lingering loop devices from previous runs..."
for dev in $(sudo losetup -a | grep "$DECOMPRESSED_IMAGE_NAME" | awk -F':' '{print $1}'); do
    echo "Detaching $dev..."
    sudo losetup -d "$dev" || echo "Warning: Failed to detach $dev during initial cleanup."
    wait_for_device_detach "$dev" # Ensure they are truly gone
done

echo "--- Starting image creation process ---"

# --- 1. Download Base Ubuntu Server Image (Conditional Download and Decompression) ---
if [ -f "$BASE_IMAGE_NAME" ]; then
    echo "--- Compressed base image '$BASE_IMAGE_NAME' exists. Decompressing (keeping original)... ---"
    #xz -df -k "$BASE_IMAGE_NAME" || error_exit "Failed to decompress $BASE_IMAGE_NAME."
    echo "Running: xz -dfc \"$BASE_IMAGE_NAME\" > \"$DECOMPRESSED_IMAGE_NAME\""
    xz -dfc "$BASE_IMAGE_NAME" > "$DECOMPRESSED_IMAGE_NAME" || error_exit "Failed to decompress
else #download
    echo "--- Downloading base Ubuntu Server image for Raspberry Pi 5 (${UBUNTU_RELEASE} ${ARCH}) ---"
    echo "URL: $BASE_IMAGE_URL"
    wget -q -O "$BASE_IMAGE_NAME" "$BASE_IMAGE_URL" || error_exit "Failed to download base image from $BASE_IMAGE_URL."
    echo "--- Decompressing the image (keeping original)... ---"
    #xz -df -k "$BASE_IMAGE_NAME" || error_exit "Failed to decompress $BASE_IMAGE_NAME."
    echo "Running: xz -dfc \"$BASE_IMAGE_NAME\" > \"$DECOMPRESSED_IMAGE_NAME\""
    xz -dfc "$BASE_IMAGE_NAME" > "$DECOMPRESSED_IMAGE_NAME" || error_exit "Failed to decompress
fi

# DEBUGGING: Check existence and size after decompression
echo "DEBUG: Checking existence and size of $DECOMPRESSED_IMAGE_NAME after decompression..."
ls -l "$DECOMPRESSED_IMAGE_NAME" || {
    echo "DEBUG: $DECOMPRESSED_IMAGE_NAME does NOT exist after decompression. This is a critical failure."
    error_exit "Decompressed image file missing after xz operation."
}
echo "DEBUG: $DECOMPRESSED_IMAGE_NAME exists and its details are above."


    # --- 2.5. Extend Image File (Re-enabled with a default target size for installations) ---
    echo "--- Extending image file if necessary and resizing root partition to max ---"
    # Get current size of the decompressed image in bytes
    CURRENT_SIZE_BYTES=$(stat -c %s "$DECOMPRESSED_IMAGE_NAME")
    # Target size in bytes (e.g., 8GB or 10GB for sufficient space)
    # This initial extension is to ensure enough room *before* installing desktop
    TARGET_SIZE_GB=10 # Set a reasonable size for initial operations
    TARGET_SIZE_BYTES=$((TARGET_SIZE_GB * 1024 * 1024 * 1024))

    echo "Current image file size: $((CURRENT_SIZE_BYTES / (1024*1024))) MB"
    echo "Target initial image file size: ${TARGET_SIZE_GB} GB"

    if (( CURRENT_SIZE_BYTES < TARGET_SIZE_BYTES )); then
        echo "Extending image file to ${TARGET_SIZE_GB}GB..."
        truncate -s "${TARGET_SIZE_BYTES}" "$DECOMPRESSED_IMAGE_NAME" || error_exit "Failed to extend image file."
    else
        echo "Image file is already at least ${TARGET_SIZE_GB}GB. Skipping initial extension."
    fi

# DEBUGGING: Check existence and size after truncation
echo "DEBUG: Checking existence and size of $DECOMPRESSED_IMAGE_NAME after truncation..."
ls -l "$DECOMPRESSED_IMAGE_NAME" || {
    echo "DEBUG: $DECOMPRESSED_IMAGE_NAME does NOT exist after truncation. This is a critical failure."
    error_exit "Decompressed image file missing after truncate operation."
}
echo "DEBUG: $DECOMPRESSED_IMAGE_NAME exists and its details are above."


# --- 3. Create a Loop Device for the Image (Main Loop Device for Partitioning) ---
echo "--- Attaching image to loop device for partitioning ---"
# Attach the entire image file to a loop device for initial partitioning
LOOP_DEVICE_FOR_PARTED=$(sudo losetup -f --show "$DECOMPRESSED_IMAGE_NAME")
if [ -z "$LOOP_DEVICE_FOR_PARTED" ]; then
    error_exit "Failed to create loop device for partitioning using losetup."
fi
echo "Loop device for parted created: ${LOOP_DEVICE_FOR_PARTED}"

# Wait for udev to create device nodes and verify existence
MAX_ATTEMPTS=10
ATTEMPT=0
while [ ! -b "$LOOP_DEVICE_FOR_PARTED" ] && [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    echo "Waiting for ${LOOP_DEVICE_FOR_PARTED} to appear (attempt $((ATTEMPT + 1))/${MAX_ATTEMPTS})..."
    sleep 1
    sudo udevadm settle # Ensure all udev events are processed
    ATTEMPT=$((ATTEMPT + 1))
    done

if [ ! -b "$LOOP_DEVICE_FOR_PARTED" ]; then
    error_exit "Loop device ${LOOP_DEVICE_FOR_PARTED} does not exist after $MAX_ATTEMPTS attempts and udevadm settle. Check kernel modules."
fi

# Resize the second partition (root partition) to fill the disk
echo "Resizing partition 2 (root partition) to 100% of the disk using parted..."
parted -s "${LOOP_DEVICE_FOR_PARTED}" resizepart 2 100% || error_exit "Failed to resize partition 2."

echo "Detaching loop device used for partitioning..."
sudo losetup -d "$LOOP_DEVICE_FOR_PARTED" || error_exit "Failed to detach loop device after partitioning."
wait_for_device_detach "$LOOP_DEVICE_FOR_PARTED" # Wait for it to fully disappear
LOOP_DEVICE_FOR_PARTED="" # Clear variable after detaching
sleep 2 # Give kernel time to update partition table

# DEBUGGING: Check existence and size after first loop device detachment
echo "DEBUG: Checking existence and size of $DECOMPRESSED_IMAGE_NAME after first loop device detachment..."
ls -l "$DECOMPRESSED_IMAGE_NAME" || {
    echo "DEBUG: $DECOMPRESSED_IMAGE_NAME does NOT exist after first loop device detachment. This is unexpected."
    error_exit "Decompressed image file missing after first loop device detachment."
}
echo "DEBUG: $DECOMPRESSED_IMAGE_NAME exists and its details are above."


# --- 3.5. Re-attach Loop Device with Partition Scanning ---
echo "--- Re-attaching loop device with partition scanning (-P) ---"
# This will create /dev/loopXp1, /dev/loopXp2, etc.
MAIN_LOOP_DEVICE=$(sudo losetup -P -f --show "$DECOMPRESSED_IMAGE_NAME")
if [ -z "$MAIN_LOOP_DEVICE" ]; then
    error_exit "Failed to re-create loop device with partition scanning."
fi
echo "Main loop device with partitions created: ${MAIN_LOOP_DEVICE}"

# Wait for udev to create partition device nodes
MAX_ATTEMPTS=10
ATTEMPT=0
# Assuming standard partition naming: /dev/loopXp1 and /dev/loopXp2
BOOT_PARTITION="${MAIN_LOOP_DEVICE}p1"
ROOT_PARTITION="${MAIN_LOOP_DEVICE}p2"

while ([ ! -b "$BOOT_PARTITION" ] || [ ! -b "$ROOT_PARTITION" ]) && [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    echo "Waiting for partition devices ${BOOT_PARTITION} and ${ROOT_PARTITION} to appear (attempt $((ATTEMPT + 1))/${MAX_ATTEMPTS})..."
    sleep 1
    sudo udevadm settle # Ensure all udev events are processed
    ATTEMPT=$((ATTEMPT + 1))
done

if [ ! -b "$BOOT_PARTITION" ] || [ ! -b "$ROOT_PARTITION" ]; then
    error_exit "Partition devices not found after $MAX_ATTEMPTS attempts and udevadm settle. Expected $BOOT_PARTITION and $ROOT_PARTITION."
fi
echo "Partition devices found: ${BOOT_PARTITION} and ${ROOT_PARTITION}"


# --- 4. Mount Partitions ---
echo "--- Mounting partitions ---"
mkdir -p "$BOOT_MOUNT_POINT" "$ROOT_MOUNT_POINT"

# Mount root partition
mount "$ROOT_PARTITION" "$ROOT_MOUNT_POINT" || error_exit "Failed to mount root partition."
# Mount boot partition
mount "$BOOT_PARTITION" "$BOOT_MOUNT_POINT" || error_exit "Failed to mount boot partition."

echo "Partitions mounted: $ROOT_PARTITION to $ROOT_MOUNT_POINT, $BOOT_PARTITION to $BOOT_MOUNT_POINT"

# --- 4.5. Expand Filesystem on Root Partition ---
echo "--- Expanding filesystem on root partition to fill its partition ---"
# Now that we have a direct device for the root partition, resize2fs can work on it.
resize2fs "$ROOT_PARTITION" || error_exit "Failed to resize root filesystem to max partition size."
echo "Root filesystem expanded to fill its partition."

# --- 5. Chroot into the Image and Install ---
echo "--- Chrooting into the image and installing ---"

# Bind necessary directories for chroot environment
mount --bind /dev "$ROOT_MOUNT_POINT/dev"
mount --bind /sys "$ROOT_MOUNT_POINT/sys"
mount --bind /proc "$ROOT_MOUNT_POINT/proc"
mount --bind /run "$ROOT_MOUNT_POINT/run"

# Copy DNS configuration to allow apt to resolve hosts inside chroot
#cp /etc/resolv.conf "$ROOT_MOUNT_POINT/etc/resolv.conf"

# Copy the qemu-aarch64-static binary into the chroot environment
# This is crucial for cross-architecture emulation within the chroot
echo "Copying qemu-aarch64-static for chroot emulation..."
QEMU_BIN="/usr/bin/qemu-aarch64-static"
CHROOT_QEMU_BIN="${ROOT_MOUNT_POINT}/usr/bin/qemu-aarch64-static"
# This check and copy is only relevant if running on x86_64 host for arm64 target
if [ "$(uname -m)" != "aarch64" ]; then
    if [ ! -f "$QEMU_BIN" ]; then
        error_exit "qemu-aarch64-static not found at $QEMU_BIN. Please install qemu-user-static on your host."
    fi
    cp "$QEMU_BIN" "$CHROOT_QEMU_BIN" || error_exit "Failed to copy qemu-aarch64-static to chroot."
    chmod +x "$CHROOT_QEMU_BIN"
fi


# Chroot into the mounted filesystem
# We pass the CODE_NAME variable into the chroot's shell to use in sources.list
chroot "$ROOT_MOUNT_POINT" /bin/bash <<EOF
    echo "Inside chroot environment..."

    # Configure apt to use apt-cacher-ng if it's running on the host
    if [ "$USE_APT_CACHE_NG" = "true" ]; then
        echo "Acquire::http::Proxy \"http://127.0.0.1:3142\";" > /etc/apt/apt.conf.d/01proxy
        echo "Configured apt to use apt-cacher-ng proxy."
    fi

    # Ensure 'updates' and 'backports' repositories are enabled
    echo "Ensuring 'updates' and 'backports' repositories are enabled in sources.list for ${CODE_NAME}..."
    # Add 'updates' components if not present
    if ! grep -q "${CODE_NAME}-updates" /etc/apt/sources.list; then
        echo "deb http://ports.ubuntu.com/ubuntu-ports ${CODE_NAME}-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://ports.ubuntu.com/ubuntu-ports ${CODE_NAME}-updates main restricted universe multiverse" >> /etc/apt/sources.list
    fi
    # Add 'backports' components if not present
    if ! grep -q "${CODE_NAME}-backports" /etc/apt/sources.list; then
        echo "deb http://ports.ubuntu.com/ubuntu-ports ${CODE_NAME}-backports main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://ports.ubuntu.com/ubuntu-ports ${CODE_NAME}-backports main restricted universe multiverse" >> /etc/apt/sources.list
    fi
    # Ensure security is there
    if ! grep -q "${CODE_NAME}-security" /etc/apt/sources.list; then
        echo "deb http://ports.ubuntu.com/ubuntu-ports ${CODE_NAME}-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://ports.ubuntu.com/ubuntu-ports ${CODE_NAME}-security main restricted universe multiverse" >> /etc/apt/sources.list
    fi

    # Update package lists
    echo "* start: apt update"
    DEBIAN_FRONTEND=noninteractive apt update || exit 1
    echo "* end: apt update"

    # Attempt to fix broken packages and resolve core system dependencies
    echo "* Attempting to fix broken packages and resolve core system dependencies..."
    DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y

    # Perform a full upgrade. This is crucial for bringing all packages to a consistent state.
    echo "* Performing full upgrade to resolve major conflicts and update system..."
    # Using --allow-downgrades, --allow-unauthenticated, and --force-overwrite for robustness
    DEBIAN_FRONTEND=noninteractive apt full-upgrade -y --allow-downgrades --allow-unauthenticated -o Dpkg::Options::="--force-overwrite" || {
        echo "Full-upgrade failed. Attempting to install problematic core packages explicitly."
        # If full-upgrade still fails, try to explicitly install the reported problematic packages.
        # This list of packages covers common base system components that can cause issues.
        DEBIAN_FRONTEND=noninteractive apt install -y \
            libgcrypt20 libsystemd0 libsystemd-shared \
            systemd systemd-sysv udev \
            libcurl3t64-gnutls libjansson4 libnewt0.52 \
            netplan.io netplan-generator python3-netplan || exit 1
    }

    echo "* Installing network-manager (if not already present)..."
    DEBIAN_FRONTEND=noninteractive apt install -y network-manager || exit 1

    if [ "$IMAGE_TYPE" = "desktop" ]; then
        # Install Ubuntu MATE Desktop environment
        echo "Installing ubuntu-mate-desktop..."
        DEBIAN_FRONTEND=noninteractive apt install -y ubuntu-mate-desktop || exit 1
        
        # Configure LightDM as the default display manager (MATE's default)
        echo "Configuring LightDM as default display manager..."
        DEBIAN_FRONTEND=noninteractive dpkg-reconfigure lightdm || exit 1
    fi

    # Clean up apt cache to reduce image size
    echo "Clean up apt cache to reduce image size"
    apt clean
    rm -rf /var/lib/apt/lists/*

    # Remove the apt proxy configuration file
    if [ -f "/etc/apt/apt.conf.d/01proxy" ]; then
        rm /etc/apt/apt.conf.d/01proxy
        echo "Removed apt-cacher-ng proxy configuration."
    fi

    echo "Exiting chroot environment..."
EOF

# Check if chroot commands were successful
if [ $? -ne 0 ]; then
    error_exit "Chroot operations failed. Check the commands executed within chroot."
fi

# IMPORTANT: Steps to ensure the mount point is not busy
echo "Ensuring the host script's current directory is not on the mounted filesystems..."
cd / || error_exit "Failed to change host directory to /."

echo "Synchronizing filesystem changes to disk..."
sync # Flush any pending writes to disk

echo "Waiting briefly for processes to terminate after chroot..."
sleep 2 # Give a moment for any lingering chroot processes to die

# Identify and kill any processes still holding the mount points busy.
# This is often necessary with chroots. 'fuser -km' kills processes (-k) on mount points (-m).
# Redirecting stderr to /dev/null suppresses "no process found" messages.
echo "Attempting to terminate any processes still using '$ROOT_MOUNT_POINT' or '$BOOT_MOUNT_POINT'..."
sudo fuser -km "$ROOT_MOUNT_POINT" 2>/dev/null || true # Added || true
sudo fuser -km "$BOOT_MOUNT_POINT" 2>/dev/null || true # Added || true
sleep 1 # Give processes a moment to be killed

echo "--- Unmounted bind directories ---"

# Remove copied resolv.conf
#Why?
#if [ -f "$ROOT_MOUNT_POINT/etc/resolv.conf" ]; then
#    rm "$ROOT_MOUNT_POINT/etc/resolv.conf"
#    echo "Removed /etc/resolv.conf from chroot."
#fi

# Remove the qemu-aarch64-static binary from the chroot environment
# This is only done if running on an x86_64 host
if [ "$(uname -m)" != "aarch64" ]; then
    echo "Removing qemu-aarch64-static from chroot..."
    rm "$CHROOT_QEMU_BIN" || echo "Warning: Failed to remove qemu-aarch64-static from chroot."
fi

# --- 6. Unmount Partitions BEFORE Shrinking Filesystem and Partition ---
echo "--- Unmounting partitions for filesystem and partition shrinking ---"

# First, unmount boot partition
if mountpoint -q "$BOOT_MOUNT_POINT"; then
    echo "Unmounting $BOOT_MOUNT_POINT..."
    sudo umount "$BOOT_MOUNT_POINT" || error_exit "Failed to unmount boot partition."
fi

# Now, handle the root partition with more robustness
MAX_UMOUNT_ATTEMPTS=5
UMOUNT_ATTEMPT=0
UMOUNT_SUCCESS=false

while [ $UMOUNT_ATTEMPT -lt $MAX_UMOUNT_ATTEMPTS ]; do
    UMOUNT_ATTEMPT=$((UMOUNT_ATTEMPT + 1))
    if mountpoint -q "$ROOT_MOUNT_POINT"; then
        echo "Attempting to unmount $ROOT_MOUNT_POINT (attempt $UMOUNT_ATTEMPT/$MAX_UMOUNT_ATTEMPTS)..."
        # Try to kill processes holding it busy
        echo "  Running fuser -km on $ROOT_MOUNT_POINT..."
        sudo fuser -km "$ROOT_MOUNT_POINT" 2>/dev/null || true # Added || true
        sleep 1 # Give processes a moment to die

        # Try standard unmount
        sudo umount "$ROOT_MOUNT_POINT" 2>/dev/null || true # Added || true
        if mountpoint -q "$ROOT_MOUNT_POINT"; then
            echo "  Standard unmount failed, trying lazy unmount..."
            sudo umount -l "$ROOT_MOUNT_POINT" 2>/dev/null || true # Added || true
        fi

        if mountpoint -q "$ROOT_MOUNT_POINT"; then
            echo "  Still busy. Processes currently using $ROOT_MOUNT_POINT:"
            # List processes using lsof for debugging
            sudo lsof | grep "$ROOT_MOUNT_POINT" || echo "    (No lsof output, might be kernel-level lock)"
            sleep 3 # Wait longer before next attempt
        else
            UMOUNT_SUCCESS=true
            echo "  Successfully unmounted $ROOT_MOUNT_POINT."
            break # Exit the loop if unmount succeeded
        fi
    else
        UMOUNT_SUCCESS=true
        echo "$ROOT_MOUNT_POINT is already unmounted."
        break # Already unmounted
    fi
done

if [ "$UMOUNT_SUCCESS" = "false" ]; then
    error_exit "Root partition $ROOT_MOUNT_POINT remains mounted after $MAX_UMOUNT_ATTEMPTS attempts. Manual intervention required."
fi

# --- 6.5. Shrink Filesystem and Partition ---
# JZ: Commenting out the actual shrinking process for now.
# The image will remain at the size it was initially extended to (e.g., 10GB).
# If you want to enable shrinking, uncomment the block below.

# --- START Shrinking Block (currently commented out) ---
: << 'SKIP_SHRINK_AND_RESIZE_ACTUAL_OPERATIONS'
echo "--- Shrinking filesystem on root partition ---"
# Check filesystem for errors first (important before shrinking)
sudo e2fsck -fy "$ROOT_PARTITION" || error_exit "Filesystem check failed on $ROOT_PARTITION."

# Shrink the filesystem to its minimum size
# The -M flag calculates the minimum size
echo "--- resize2fs -M $ROOT_PARTITION"
sudo resize2fs -M "$ROOT_PARTITION" || error_exit "Failed to shrink root filesystem to minimum."

# Get the new size of the filesystem in blocks and block size
# It's safer to get the size in 1K blocks from tune2fs -l.
# We also add a buffer for safety (e.g., 200MB)
echo "Getting new filesystem size for partition resize..."
FS_SIZE_KB=$(sudo tune2fs -l "$ROOT_PARTITION" | grep 'Block count:' | awk '{print $3}')
FS_BLOCK_SIZE_BYTES=$(sudo tune2fs -l "$ROOT_PARTITION" | grep 'Block size:' | awk '{print $3}')
FS_SIZE_BYTES=$((FS_SIZE_KB * FS_BLOCK_SIZE_BYTES)) # Convert to bytes

# Add a safety buffer (e.g., 200MB) to the filesystem size, to ensure enough space for partition table alignment
BUFFER_BYTES=$((200 * 1024 * 1024)) # 200 MB buffer
TARGET_PARTITION_SIZE_BYTES=$((FS_SIZE_BYTES + BUFFER_BYTES))

echo "Filesystem shrunk to approximately $((FS_SIZE_BYTES / (1024*1024))) MB."
echo "Target partition size (including buffer): $((TARGET_PARTITION_SIZE_BYTES / (1024*1024))) MB"

# Detach the main loop device so we can use sgdisk to modify the partition table
echo "Detaching main loop device to resize partition..."
if [ -n "$MAIN_LOOP_DEVICE" ] && sudo losetup -a | grep -q "$MAIN_LOOP_DEVICE"; then
    sudo losetup -d "$MAIN_LOOP_DEVICE" || error_exit "Failed to detach main loop device before partition shrink."
    wait_for_device_detach "$MAIN_LOOP_DEVICE" # Ensure it's fully detached
    MAIN_LOOP_DEVICE="" # Clear variable
fi
sleep 2 # Give kernel time

echo "Re-attaching loop device for partition table manipulation..."
# Need a loop device for the whole image to modify the partition table
LOOP_DEVICE_FOR_PARTED=$(sudo losetup -f --show "$DECOMPRESSED_IMAGE_NAME")
if [ -z "$LOOP_DEVICE_FOR_PARTED" ]; then
    error_exit "Failed to create loop device for partition table modification."
fi
echo "Loop device for partition table modification: ${LOOP_DEVICE_FOR_PARTED}"
sleep 2 # Give kernel time for device nodes

# Get the start sector of the root partition
ROOT_START_SECTOR=$(sudo fdisk -l "$LOOP_DEVICE_FOR_PARTED" | grep "${LOOP_DEVICE_FOR_PARTED}p2" | awk '{print $2}')
if [ -z "$ROOT_START_SECTOR" ]; then
    error_exit "Could not determine start sector of root partition."
fi
echo "Root partition starts at sector: ${ROOT_START_SECTOR}"

# Calculate new end sector based on target size (sectors = (size_bytes / 512) + start_sector - 1)
SECTOR_SIZE=512
TARGET_PARTITION_END_SECTOR=$((ROOT_START_SECTOR + (TARGET_PARTITION_SIZE_BYTES / SECTOR_SIZE) - 1))

echo "Recreating partition 2 with new end sector using sgdisk..."
sudo sgdisk -d 2 "$LOOP_DEVICE_FOR_PARTED" || error_exit "Failed to delete partition 2 with sgdisk."
# The -n option syntax is -n part_num:start_sector:end_sector. End sector is inclusive.
sudo sgdisk -n 2:"${ROOT_START_SECTOR}":"${TARGET_PARTITION_END_SECTOR}" "$LOOP_DEVICE_FOR_PARTED" || error_exit "Failed to create new partition 2 with sgdisk."
# Set the partition type to Linux filesystem (0x8300 for GUID Partition Table)
sudo sgdisk -t 2:8300 "$LOOP_DEVICE_FOR_PARTED" || error_exit "Failed to set partition type with sgdisk."

# Inform the kernel of the partition table changes
sudo partprobe "$LOOP_DEVICE_FOR_PARTED" || echo "Warning: partprobe failed, but often fine."
sleep 5 # Give kernel time to process new partition table

echo "Detaching loop device used for partition table modification..."
sudo losetup -d "$LOOP_DEVICE_FOR_PARTED" || error_exit "Failed to detach loop device after partition table modification."
wait_for_device_detach "$LOOP_DEVICE_FOR_PARTED" # Ensure it's fully detached
LOOP_DEVICE_FOR_PARTED="" # Clear variable after detaching
sleep 2 # Give kernel time

# --- Re-attach loop device with partition scanning to verify the new size ---
echo "--- Re-attaching loop device with partition scanning to verify new size ---"
MAIN_LOOP_DEVICE=$(sudo losetup -P -f --show "$DECOMPRESSED_IMAGE_NAME")
if [ -z "$MAIN_LOOP_DEVICE" ]; then
    error_exit "Failed to re-create loop device with partition scanning after shrink."
fi
echo "Main loop device with partitions created for final check: ${MAIN_LOOP_DEVICE}"

# Wait for udev to create partition device nodes
MAX_ATTEMPTS=10
ATTEMPT=0
BOOT_PARTITION="${MAIN_LOOP_DEVICE}p1"
ROOT_PARTITION="${MAIN_LOOP_DEVICE}p2" # This will now reflect the shrunk size

while ([ ! -b "$BOOT_PARTITION" ] || [ ! -b "$ROOT_PARTITION" ]) && [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    echo "Waiting for partition devices ${BOOT_PARTITION} and ${ROOT_PARTITION} to appear (attempt $((ATTEMPT + 1))/${MAX_ATTEMPTS})..."
    sleep 1
    sudo udevadm settle
    ATTEMPT=$((ATTEMPT + 1))
done

if [ ! -b "$BOOT_PARTITION" ] || [ ! -b "$ROOT_PARTITION" ]; then
    error_exit "Partition devices not found after $MAX_ATTEMPTS attempts and udevadm settle after shrink."
fi
echo "--- Partition devices found after shrink: ${BOOT_PARTITION} and ${ROOT_PARTITION}"

# Final check of filesystem size and resize to fit new partition
echo "--- Re-checking filesystem size on ${ROOT_PARTITION} and resizing to fit new partition..."
sudo e2fsck -fy "$ROOT_PARTITION" || error_exit "Final filesystem check failed."
sudo resize2fs "$ROOT_PARTITION" # Resizes to the *new* partition size

# Get actual image size needed and truncate the image file
echo "Calculating new image file size and truncating..."
# Get the end sector of the *last* partition (which is partition 2)
# Add a small buffer for the GPT table overhead (e.g., 20MB)
LAST_SECTOR=$(sudo fdisk -l "$MAIN_LOOP_DEVICE" | grep "${MAIN_LOOP_DEVICE}p2" | awk '{print $3}') # End sector of the last partition
# Calculate the total image size needed based on the last sector of the last partition
# Image size needs to cover the entire last partition + some overhead for the GPT backup header.
# A general rule is to calculate bytes from the last sector and add a few MBs.
SECTOR_SIZE=512
IMAGE_FILE_SIZE_BYTES=$(((LAST_SECTOR + 1) * SECTOR_SIZE + (20 * 1024 * 1024))) # Add 20MB safety buffer

echo "--- Truncating image file to ${IMAGE_FILE_SIZE_BYTES} bytes."
truncate -s "$IMAGE_FILE_SIZE_BYTES" "$DECOMPRESSED_IMAGE_NAME" || error_exit "Failed to truncate image file."

echo "--- Image file shrunk successfully. ---"
SKIP_SHRINK_AND_RESIZE_ACTUAL_OPERATIONS
# --- END Shrinking Block ---

# IMPORTANT: Ensure the main loop device is detached *before* renaming the file.
# If shrinking is skipped (as currently configured), MAIN_LOOP_DEVICE is still active from section 3.5.
# We must detach it here before attempting to move the underlying image file.
echo "--- Detaching main loop device before final image rename ---"
if [ -n "$MAIN_LOOP_DEVICE" ] && sudo losetup -a | grep -q "$MAIN_LOOP_DEVICE"; then
    sudo losetup -d "$MAIN_LOOP_DEVICE" || error_exit "Failed to detach main loop device before renaming image."
    wait_for_device_detach "$MAIN_LOOP_DEVICE"
    MAIN_LOOP_DEVICE="" # Clear variable after detaching
    sync # Added: Ensure all pending writes are flushed to disk
    sleep 2 # Added: Give a moment for the filesystem to settle
    # NEW DEBUG LINE HERE
    echo "DEBUG: Checking existence of $DECOMPRESSED_IMAGE_NAME immediately after main loop device detachment and sync/sleep..."
    #read -p "Press Enter to continue..." # Replaced 'pause' with 'read -p'
    ls -l "$DECOMPRESSED_IMAGE_NAME" || {
        echo "DEBUG: $DECOMPRESSED_IMAGE_NAME does NOT exist immediately after detachment. This is the source of the problem."
        error_exit "Decompressed image file missing immediately after main loop device detachment."
    }
    echo "DEBUG: $DECOMPRESSED_IMAGE_NAME exists immediately after detachment."
fi

# --- 7. Finalize Image ---
echo "--- Renaming the updated image file ---"
# DEBUGGING: Check file existence before mv
echo "DEBUG: Checking existence of $DECOMPRESSED_IMAGE_NAME before mv..."
ls -l "$DECOMPRESSED_IMAGE_NAME" || {
    echo "DEBUG: $DECOMPRESSED_IMAGE_NAME does NOT exist right before mv. This is unexpected."
    error_exit "Source image file missing before rename operation."
}
echo "DEBUG: $DECOMPRESSED_IMAGE_NAME exists."

mv "$DECOMPRESSED_IMAGE_NAME" "$OUTPUT_IMAGE_NAME" || error_exit "Failed to rename the updated image."

echo "--- Compressing the final image for distribution ---"
echo "Output will be: ${COMPRESSED_OUTPUT_IMAGE_NAME}"
#will 2 threads vs unlimited help?
#xz -z -k -T 0 "$OUTPUT_IMAGE_NAME" || error_exit "Failed to compress the final image."
xz -z -k -T 2 "$OUTPUT_IMAGE_NAME" || error_exit "Failed to compress the final image."

echo "--- Image creation complete! ---"
echo "Your image is ready at: ${COMPRESSED_OUTPUT_IMAGE_NAME}"
echo "Script finished."

exit 0
