#!/bin/bash
set -eo pipefail

src_dir=$PWD

mkdir -p ../../build/bip85_rsa_key_gen
cd ../../build/bip85_rsa_key_gen
cmake ${src_dir} -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

test_mnemonic="fish inner face ginger orchard permit useful method fence kidney chuckle party favorite sunset draw limb science crane oval letter slot invite sadness banana"
test_xpriv="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
test_passphrase="bip85_rsa_key_gen"

generate_key() {
    local index=$1
    local key_bits=$2
    local input_type=$3
    local input_value=$4
    local passphrase=$5

    local filename="key_${input_type}_${index}_${key_bits}"
    if [ -n "${passphrase}" ]; then
        filename="${filename}_passphrase_${passphrase}"
    fi
    ./bip85_rsa_key_gen --index ${index} --key_bits ${key_bits} ${input_type} "${input_value}" ${passphrase:+--passphrase "${passphrase}"} > ${src_dir}/test_vectors/${filename}.txt
}

for key_bits in 1024 2048 3072 4096; do
    for i in {0..3}; do
        generate_key $i ${key_bits} --mnemonic "${test_mnemonic}"
        generate_key $i ${key_bits} --mnemonic "${test_mnemonic}" "${test_passphrase}"
        generate_key $i ${key_bits} --xpriv "${test_xpriv}"
    done
done
