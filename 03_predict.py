# -*- coding:utf-8 -*-
import argparse
import pandas as pd
from core import GetFeatures
import tqdm
import os
import pickle
from sklearn.externals import joblib
import pefile
import sys

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--model', required=True, help="model and feture directory")
parser.add_argument('-d', '--datadir', required=True, help="predict dataset directory")
parser.add_argument('-c', '--csv', required=True, help="predict dataset label")
parser.add_argument('-o', '--output', required=True, help="output directory")
args = parser.parse_args()

if not os.path.exists(args.model):
    parser.error("{} does not exist".format(args.model))
if not os.path.exists(args.datadir):
    parser.error("{} does not exist".format(args.datadir))
if not os.path.exists(args.csv):
    parser.error("{} does not exist".format(args.csv))
if not os.path.exists(args.output):
    os.mkdir(args.output)

def predict():
    #load model
    clf = joblib.load(os.path.join(args.model, 'classifier.pkl'))
    data = pd.read_csv(args.csv, names=['hash', 'y'])
    
    #predict
    y_pred = []
    y = []
    filename= []
    errcount = 0

    for _file in tqdm.tqdm(os.listdir(args.datadir)):
        _path = os.path.join(args.datadir, _file)
        y.append(data[data.hash==_file].values[0][1])
        filename.append(_file)
        try:
            pe_features = GetFeatures(_path)
            res = clf.predict([pe_features])
            y_pred.append(res[0])
        except KeyboardInterrupt:
            sys.exit()
        except:
            y_pred.append(0)
            errcount += 1

    df = pd.DataFrame({'hash': filename, 'y':y, 'ypred':y_pred})
    df.to_csv(os.path.join(args.output, 'result.csv'), index=False)
    print("error {} is occured".format(errcount))

def main():
    predict()

if __name__=='__main__':
    main()