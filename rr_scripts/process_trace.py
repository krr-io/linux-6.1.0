

def process_tcg_file(input_file, output_file):
    lines = []
    with open(output_file, "a+") as o:
        with open(input_file, "r") as r:
            for line in r.readlines():
                if line.startswith("0xffff"):
                    o.write(line.split()[0][:-1] + '\n')


def process_kvm_file(input_file, output_file):
    lines = []
    with open(output_file, "a+") as o:
        with open(input_file, "r") as r:
            last = None
            for line in r.readlines():
                lines = line.split()
                inst = str(lines[1])
                if inst.startswith("0xffff"):
                    cur = inst
                    if last is None or cur != last:
                        o.write(cur + '\n')
                    last = cur


if __name__ == "__main__":
    process_tcg_file("/home/projects/qemu-tcg-kvm/build/rec.log", "./rr_scripts/tcg_trace")
    process_kvm_file("/home/projects/linux-6.1.0/rr_scripts/record-trace", "./rr_scripts/kvm_trace")
