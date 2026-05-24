import zipfile
p='space_cleaner/release/SpaceCleaner_Portable.zip'
with zipfile.ZipFile(p) as z:
    for n in z.namelist():
        print(n)
