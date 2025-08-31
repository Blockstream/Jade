#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

cleanup() {
  rm -rf -- "${temp_directory}"
  if [ -n "${initial_tty_device_permissions:-}" ] &&
    [ "$(stat -c '%a' "${tty_device}")" != "${initial_tty_device_permissions}" ]; then
    sudo chmod "${initial_tty_device_permissions}" "${tty_device}"
  fi
}

working_directory="${HOME}/Downloads/diy_jade"
temp_directory="${working_directory}/temp"
trap cleanup EXIT

jade_git_tag="master"
jade_save_directory="${working_directory}/jade"
jade_repo_url="https://github.com/danielboro/jade.git"

esp_idf_git_tag="v5.4.2"
esp_idf_temp_directory="${temp_directory}/esp-idf"
esp_idf_save_directory="${working_directory}/esp-idf"
esp_idf_repo_url="https://github.com/espressif/esp-idf.git"

chosen_device="TTGO T-Display"
tty_device="/dev/ttyACM0"

clear
echo "------------------------------------------------------------"
echo "------------------------------------------------------------"
echo "---                                                      ---"
echo "---          Do-It-Yourself Jade Install Script          ---"
echo "---                Written by Epic Curious               ---"
echo "---                                                      ---"
echo "------------------------------------------------------------"
echo "------------------------------------------------------------"
echo

if [ "$(whoami)" = "root" ]; then
  echo -e "ALERT: You're running the script as root/superuser.\nYou may notice PIP 'sudo -H' warnings.\n"
fi

echo "LINUX ONLY. Flashing the ${chosen_device}..."

while read -r dependency; do
  if ! command -v "${dependency}" &> /dev/null; then
    echo -en "\n\nERROR:\n${dependency} was not found on your system.\nPlease install ${dependency} by running:\n\n"
    if [ "${dependency}" == "pip" ] || [ "${dependency}" == "virtualenv" ]; then
      echo -en "sudo apt update && sudo apt install -y python3-${dependency}\n\n"
    else
      echo -en "sudo apt update && sudo apt install -y ${dependency}\n\n"
    fi
    exit 1
  fi
done < <(curl -fsSL https://github.com/epiccurious/jade-diy/raw/master/depends.txt)

if [ ! -f "${esp_idf_save_directory}"/export.sh ]; then
  git clone --branch "${esp_idf_git_tag}" --single-branch --depth 1 "${esp_idf_repo_url}" "${esp_idf_temp_directory}"
  cd "${esp_idf_temp_directory}"/
  git submodule update --depth 1 --init --recursive
  ./install.sh esp32 &> /dev/null
  source ./export.sh 1> /dev/null
  mv "${esp_idf_temp_directory}" "${esp_idf_save_directory}"
fi
cd "${esp_idf_save_directory}"/
./install.sh esp32
source ./export.sh

if [ ! -d "${jade_save_directory}" ]; then
  git clone --branch "${jade_git_tag}" --single-branch --depth 1 "${jade_repo_url}" "${jade_save_directory}"
  cd "${jade_save_directory}"
  git submodule update --depth 1 --init --recursive &> /dev/null
fi
cd "${jade_save_directory}"
jade_version="$(git describe --tags)"

cp configs/sdkconfig_display_ttgo_tdisplay.defaults sdkconfig.defaults
sed -i.bak '/CONFIG_DEBUG_MODE/d' ./sdkconfig.defaults
sed -i.bak '1s/^/CONFIG_LOG_DEFAULT_LEVEL_NONE=y\n/' sdkconfig.defaults
rm sdkconfig.defaults.bak

idf.py build

[ "${CI:-false}" = true ] && echo "Exiting the script for CI runners." && exit 0

while [ ! -c "${tty_device}" ]; do
  read -srn1 -p "Connect your ${chosen_device} and PRESS ANY KEY to continue... " && echo
done
initial_tty_device_permissions="$(stat -c '%a' "${tty_device}")"
if [ "${initial_tty_device_permissions:2}" -lt 6 ]; then
  echo -e "\nElevating write permissions for ${chosen_device}"
  sudo chmod o+rw "${tty_device}"
  echo
fi

idf.py flash

echo -e "\nSUCCESS! Jade ${jade_version} is now installed on your ${chosen_device}.\nYou can close this window.\n"