import os

TARGET_EXT = ['.py', '.js', '.jsx'] # file extension

def dump_all_files(root=".", output_name="output.txt"):
    collected = []
    for dirpath, _, filenames in os.walk(root):
        for f in filenames:
            _, ext = os.path.splitext(f)
            if ext in TARGET_EXT:
                full_path = os.path.join(dirpath, f)
                rel_path = os.path.relpath(full_path, root)

                with open(full_path, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()

                collected.append(f'"""\n{content}\n""" {rel_path}')

    with open(output_name, "w", encoding="utf-8") as out:
        out.write("\n\n".join(collected))


dump_all_files(".")
