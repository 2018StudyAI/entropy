import pefile
import os
import pandas as pd
import sys
import argparse
import tqdm

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--datadir', type=str, help='trainset directory')
parser.add_argument('-o', '--output', type=str, help='output directory')
parser.add_argument('-c', '--csv', type=str, help='trainset label')
args = parser.parse_args()

#troubleshooting on argument
if not os.path.exists(args.datadir):
    parser.error("trainset {} doesn't exist ".format(args.datadir))
if not os.path.exists(args.csv):
    parser.error("trainset label {} doesn't exist".format(args.csv))
if not os.path.exists(args.output):
    os.mkdir(args.output)

#get section including entrypoint
def GetEntryPointSections(pe):
    offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    
    for i in range(0, pe.FILE_HEADER.NumberOfSections):
        section = pe.sections[i]
        if offset > section.PointerToRawData and offset <  section.PointerToRawData + section.SizeOfRawData:
            return section
    
    return -1
            
#extract entropy of section that include entrypoint
#but, some packed pefile doesn't have entrypoint. these file assert error
def GetFeatures(path):
    features = []
    pe = pefile.PE(path)
    
    EPSection = GetEntryPointSections(pe)
    if EPSection == -1:
        return -1

    #Characteristics Write charactics, 
    #I think that this is not useful for training. therefore, I omit it.

    # WriteCharacteris = EPSection.Characteristics & 0x80000000
    
    # if WriteCharacteris != 0:
    #     features.append(EPSection.get_entropy())
    # else:
    #     return -1

    features.append(EPSection.get_entropy())
    return features[0]

def main():
    #read trainset label
    TrainTable = pd.read_csv(args.csv, names=['hash', 'y'])

    #extract features
    records = []
    for _file in tqdm.tqdm(os.listdir(args.datadir)):
        FullPath = os.path.join(args.datadir, _file)
        FileSize = os.path.getsize(FullPath)
        
        #if size of pefile over 1024kbytes, the program skip the pefile
        if FileSize < 1024:
            continue
        
        #extract entropy and append to list
        #if error is occured, while getting peformat from trainset, this file is skipped
        values = []
        try:        
            feature =  GetFeatures(FullPath)
            if feature != -1:
                y = TrainTable[TrainTable.hash == _file].values[0][1]

                values.append(_file) 
                values.append(feature)
                values.append(y)

                records.append(values)
        except KeyboardInterrupt:
            sys.exit()
        except:
            print("Error : ", _file) #skip the error file
    
    #save the features
    df = pd.DataFrame(records)
    df.to_csv(os.path.join(args.output, 'features.csv'), index=False, header=None)

if __name__ == '__main__':
    main()    