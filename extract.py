import os

# Get warning IP list
def read_warning_file(warning_filename):
    warning_file = open(warning_filename, 'r')
    suspects = [aline.strip() for aline in warning_file]
    warning_file.close()
    return suspects


# Find all suspect connection logs
def detection_suspect(log_filename, warning_filename, output_filename):
    connexion_file = open(log_filename, 'r')

    if os.path.isfile(output_filename):
        os.remove(output_filename)

    output_file = open(output_filename, 'w')

    warning_list = read_warning_file(warning_filename)

    for aline in connexion_file:
        suspect_ip = aline.split(";")[0].strip()
        if suspect_ip in warning_list:
            output_file.write(aline)

    connexion_file.close()
    output_file.close()


if __name__ == "__main__":
    detection_suspect("connexion.log", "warning.txt", "suspect.log")
