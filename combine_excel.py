import pandas as pd

def dedup(lst):

    lower = (map(lambda x: x.lower(), lst))
    lowered = list(lower)

    dedup_list = list(dict.fromkeys(lowered))

    # initialize an empty string
    str1 = ""

    if type(dedup_list) == list:
    # traverse in the string

        if len(dedup_list ) > 1:

            listToStr = '~'.join([str(elem) for elem in dedup_list ])


            str1 = listToStr.replace("~", ", ")

            # return string
            return str1.replace("nil, ", "")

        else:

            listToStr = "".join([str(elem) for elem in dedup_list])

            str1 = listToStr

            return str1.replace("nil, ", "")

    else:

        # return string
        return dedup_list.replace("nil, ", "")

def dedup_within(df):

    index_list = df.index.tolist()

    for id in index_list:

        df.loc[id, ['Threat Actor']] = dedup(df["Threat Actor"].loc[id].split(","))
        df.loc[id, ['URL']] = dedup(df["URL"].loc[id].split(","))
        df.loc[id, ['country']] = dedup(df["country"].loc[id].split(","))
        df.loc[id, ['motivation']] = dedup(df["motivation"].loc[id].split(", "))
        df.loc[id, ['first seen']] = dedup(df["first seen"].loc[id].split(","))
        df.loc[id, ['sponsor']] = dedup(df["sponsor"].loc[id].split(","))
        df.loc[id, ['description']] = dedup(df["description"].loc[id].split(","))
        df.loc[id, ['observed sector']] = dedup(df["observed sector"].loc[id].split(","))
        df.loc[id, ['observed countries']] = dedup(df["observed countries"].loc[id].split(","))
        df.loc[id, ['tools']] = dedup(df["tools"].loc[id].split(","))
        df.loc[id, ['information']] = dedup(df["information"].loc[id].split(","))
        df.loc[id, ['mitre attack']] = dedup(df["mitre attack"].loc[id].split(","))
        df.loc[id, ['playbook']] = dedup(df["playbook"].loc[id].split(","))
        df.loc[id, ['industry class']] = dedup(df["industry class"].loc[id].split(","))
        df.loc[id, ['associated groups']] = dedup(df["associated groups"].loc[id].split(","))
        df.loc[id, ['id2']] = dedup(df["id2"].loc[id].split(","))

    return df

def process(a, b):

    lst = list((a + ", " + b).split(", "))

    lower = (map(lambda x: x.lower(), lst))
    lowered = list(lower)

    dedup_list = list(dict.fromkeys(lowered))

    # initialize an empty string
    str1 = ""

    if type(dedup_list) == list:
    # traverse in the string

        if len(dedup_list ) > 1:

            listToStr = '~'.join([str(elem) for elem in dedup_list ])

            str1 = listToStr.replace("~", ", ")
            # return string
            return str1.replace(", nil", "")
        else:

            listToStr = "".join([str(elem) for elem in dedup_list])

            str1 = listToStr

            return str1.replace(", nil", "")

    else:

        # return string
        return dedup_list.replace(", nil", "")


def dedup_list(lst):

    dedup_list = list(dict.fromkeys(lst))

    return dedup_list

def check_intersection(a_set, b_set, check, id_list, id):

    if (a_set & b_set):

        id_list.append(id)
        check.append(1)

    else:

        id_list.append(0)
        check.append(0)

    return id_list, check

def lower_case(lst):
    lower = (map(lambda x: x.lower(), lst))
    lowered = list(lower)

    return lowered

id_lst_etda_aptmap = []
id_lst_common = []
id_lst_special = []

input_filepath_etda_aptmap = "C:\\Users\\Admin\\Downloads\\Combined\\March_2023\\28-03-2023_final.xlsx"
input_filepath_excel = "C:\\Users\\Admin\\Downloads\\APT_Excel\\excel_combine_names.xlsx"
output_filepath = "C:\\Users\\Admin\\Downloads\\APT_Excel\\etda_aptmap_w_id.xlsx"
output_filepath2 = "C:\\Users\\Admin\\Downloads\\APT_Excel\\pre_etda_aptmap_excel.xlsx"
output_filepath3 = "C:\\Users\\Admin\\Downloads\\APT_Excel\\post_etda_aptmap_excel.xlsx"
output_filepath4 = "C:\\Users\\Admin\\Downloads\\APT_Excel\\final_etda_aptmap_excel.xlsx"

df_etda_aptmap = pd.read_excel(input_filepath_etda_aptmap)

df_excel = pd.read_excel(input_filepath_excel)

df_excel2 = pd.read_excel(input_filepath_excel)

# ----------------------------------Get Max ID----------------------------------------#

max_id = max(df_excel["id"].values.tolist())

# -----------------------------------Add ID to Etda_APTMap----------------------------------------#
for index, row in df_etda_aptmap.iterrows():

    etda_aptmap_lowercase = lower_case(list(row["Threat Actor"].split(", ")))

    a_set = set(etda_aptmap_lowercase)

    check = []
    id_list = []

    for index2, row2 in df_excel.iterrows():
        excel_lowercase = lower_case(list(row2["Common Name"].split(", ")))

        b_set = set(excel_lowercase)

        id_list, check = check_intersection(a_set, b_set, check, id_list, row2["id"])

    id_list_dedup = dedup_list(id_list)

    if len(id_list_dedup) <= 2:

        unify_id = sum(id_list_dedup)
        special_id = 0

    else:

        unify_id = id_list_dedup[1]
        special_id = id_list_dedup[2]


    if sum(check) == 0:

        max_id += 1

        id_lst_etda_aptmap.append(max_id)
        id_lst_special.append(special_id)

    else:

        id_lst_common.append(unify_id)
        id_lst_etda_aptmap.append(unify_id)
        id_lst_special.append(special_id)

df_etda_aptmap["id"] = id_lst_etda_aptmap
df_etda_aptmap["id2"] = id_lst_special

# --------------------------------------------------------------------------------------------------------------#

for i in range(len(df_etda_aptmap["Threat Actor"])):

    df_etda_aptmap["Origin"] = "nil"
    df_etda_aptmap["Targets"] = "nil"
    df_etda_aptmap["Modus Operandi"] = "nil"

df_dedup = df_etda_aptmap.groupby(['id']).agg(lambda col: ','.join(map(str, col)))

df_dedup_within = dedup_within(df_dedup)



my_dict = {}
my_dict2 = {}
index_list = []


for index, row in df_dedup_within.iterrows():


    try:
        int_row = int(row["id2"])

        if int_row != 0:

            my_dict.update({ index : int(row["id2"])})

            index_list.append(index)

        else:

            no_action = "no_action"

    except ValueError:

        my_dict2.update({index: list(row["id2"].split(", "))})

        index2 = index

df_dedup_within.to_excel(output_filepath)





# -----------------------------------Phase 1 - Combine Etda_APTMap_Excel----------------------------------------#

#df_dedup.set_index('id', inplace=True)
df_excel.set_index('id', inplace=True)

# df.loc[10, ['Threat Actor']] = ["APT 20, Violin Panda"]

dedup = dedup_list(id_lst_common)

for id in dedup:

    df_dedup_within.loc[id, ["Threat Actor"]] = \
        [process(df_dedup_within["Threat Actor"].loc[id], df_excel["Common Name"].loc[id])]

    df_dedup_within.loc[id, ["tools"]] = \
        [process(df_dedup_within["tools"].loc[id], df_excel["Toolset / Malware"].loc[id])]

    df_dedup_within.loc[id, ['mitre attack']] = \
            [process(df_dedup_within["mitre attack"].loc[id], df_excel["MITRE ATT&CK"].loc[id])]

    df_dedup_within.loc[id, ['Origin']] =  df_excel["Origin"].loc[id]

    df_dedup_within.loc[id, ['Targets']] = df_excel["Targets"].loc[id]

    df_dedup_within.loc[id, ['Modus Operandi']] =  df_excel["Modus Operandi"].loc[id]

df_dedup_within.to_excel(output_filepath2)

for i in index_list:

    print(str(i) + " : ")
    print(my_dict[i])

print(my_dict2[index2])


# -----------------------------------Phase 2 - Combine Etda_APTMap_Excel----------------------------------------#

# df.loc[10, ['Threat Actor']] = ["APT 20, Violin Panda"]

for id in index_list:

    print(df_excel2["Common Name"].loc[my_dict[id]])

    df_dedup_within.loc[id, ['Threat Actor']] = \
        [process(df_dedup["Threat Actor"].loc[id], df_excel2["Common Name"].loc[my_dict[id]])]

    df_dedup_within.loc[id, ['tools']] = \
        [process(df_dedup_within["tools"].loc[id], df_excel2["Toolset / Malware"].loc[my_dict[id]])]

    df_dedup_within.loc[id, ["mitre attack"]] = \
        [process(df_dedup_within["mitre attack"].loc[id], df_excel2["MITRE ATT&CK"].loc[my_dict[id]])]

    df_dedup_within.loc[id, ['Origin']] = \
        [process(df_dedup_within["Origin"].loc[id], df_excel2["Origin"].loc[my_dict[id]])]

    df_dedup_within.loc[id, ['Targets']] = \
        [process(df_dedup_within["Targets"].loc[id], df_excel2["Targets"].loc[my_dict[id]])]

    df_dedup_within.loc[id, ['Modus Operandi']] = \
        [process(df_dedup_within["Modus Operandi"].loc[id], df_excel2["Modus Operandi"].loc[my_dict[id]])]

df_dedup_within.to_excel(output_filepath3)

# -----------------------------------Phase 3 - Combine Etda_APTMap_Excel----------------------------------------#


# df.loc[10, ['Threat Actor']] = ["APT 20, Violin Panda"]

for id in my_dict2[index2]:

    if id != '0':

        print(df_excel2["Common Name"].loc[int(id)])

        df_dedup_within.loc[index2, ['Threat Actor']] = \
            [process(df_dedup["Threat Actor"].loc[index2], df_excel2["Common Name"].loc[int(id)])]

        df_dedup_within.loc[index2, ['tools']] = \
            [process(df_dedup_within["tools"].loc[index2], df_excel2["Toolset / Malware"].loc[int(id)])]

        df_dedup_within.loc[index2, ["mitre attack"]] = \
            [process(df_dedup_within["mitre attack"].loc[index2], df_excel2["MITRE ATT&CK"].loc[int(id)])]

        df_dedup_within.loc[index2, ['Origin']] = \
            [process(df_dedup_within["Origin"].loc[index2], df_excel2["Origin"].loc[int(id)])]

        df_dedup_within.loc[index2, ['Targets']] = \
            [process(df_dedup_within["Targets"].loc[index2], df_excel2["Targets"].loc[int(id)])]

        df_dedup_within.loc[index2, ['Modus Operandi']] = \
            [process(df_dedup_within["Modus Operandi"].loc[index2], df_excel2["Modus Operandi"].loc[int(id)])]

df_dedup_within.to_excel(output_filepath4)
