import os


# Get warning IP list
def read_warning_file(warning_filename):
    warning_file = open(warning_filename, 'r')
    suspects = set([aline.strip() for aline in warning_file])
    warning_file.close()
    return suspects


# Write the suspect list in file
def write_o_file(output_filename, suspect_list):
    if os.path.isfile(output_filename):
        os.remove(output_filename)

    output_file = open(output_filename, 'w')
    for ele in suspect_list:
        output_file.write("{}:  {} \n".format(ele["username"], str(ele["connexion_time"])))
    output_file.close()


# Detect all users who is connected other time between 8h and 19h
def detection_out_of_hour(log_filename):
    connexion_file = open(log_filename, 'r')
    out_of_hour_list = [line[1] for line in connexion_file if not (8 <= int(line.split(";")[2].split()[:2]) <= 19)]
    print(out_of_hour_list)


# Write the suspect list in file
def detection_in_warning_list(log_filename, warning_filename):
    warning_list = read_warning_file(warning_filename)
    connexion_file = open(log_filename, 'r')

    suspect_in_warning_list = [line for line in connexion_file if line.split(";")[0] in warning_list]
    return suspect_in_warning_list, connexion_file


# Count suspect connexion time and write in file
def write_suspect(log_filename, warning_filename, output_filename):
    suspect_in_warning_list, file = detection_in_warning_list(log_filename, warning_filename)
    full_text = "".join(suspect_in_warning_list)
    suspect_ip_set = set([line.split(";")[1] for line in suspect_in_warning_list])
    suspect_list = sorted([{"username": username, "connexion_time": full_text.count(username)} for username in suspect_ip_set], key=lambda d: d['connexion_time'], reverse=True)
    write_o_file(output_filename, suspect_list)
    file.close()


if __name__ == "__main__":
    detection_out_of_hour("connexion.log")
    write_suspect("connexion.log", "warning.txt", "suspect.txt")
