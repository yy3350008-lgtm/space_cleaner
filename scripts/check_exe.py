p='space_cleaner/release/SpaceCleaner_Portable/SpaceCleaner.exe'
with open(p,'rb') as f:
    hdr = f.read(2)
print(hdr)
