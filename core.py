# -*- coding:utf-8 -*-
import pefile

'''
    엔트리 포인트가 포함된 섹션 찾기
    리턴 값 : 엔트리포인트가 포함된 섹션의 인덱스
            실패시 -1 리턴
'''
def GetEntryPointSections(pe):
    offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    
    for i in range(0, pe.FILE_HEADER.NumberOfSections):
        section = pe.sections[i]
        if offset > section.PointerToRawData and offset <  section.PointerToRawData + section.SizeOfRawData:
            return section
    
    return -1
            
'''
    특징 추출
        1. 엔트리 포인트가 포함된 섹션의 엔트로피
    리턴값 : 리스트
'''
def GetFeatures(path):
    features = []
    pe = pefile.PE(path) #PE포맷 가져오기
    
    #엔트리포인트가 포함된 섹션 인덱스 가져오기
    EPSection = GetEntryPointSections(pe)
    if EPSection == -1:
        features.append(-1)

    # #1. Characteristics의 Write속성
    # WriteCharacteris = EPSection.Characteristics & 0x80000000
    
    # if WriteCharacteris != 0:
    #     features.append(EPSection.get_entropy())
    # else:
    #     return -1
    else:
        features.append(EPSection.get_entropy())
    
    return features