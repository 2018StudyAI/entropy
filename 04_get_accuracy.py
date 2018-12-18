from sklearn.metrics import confusion_matrix, accuracy_score, classification_report, roc_curve
import pandas as pd
import numpy as np
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--csv', type=str, required=True, help='csv file for getting accuracy')
parser.add_argument('-t', '--threshold', type=str, default=0.99, help='threadshold for predicting')
args = parser.parse_args()

def main():
    data = pd.read_csv(args.csv)
    
    y = data.y
    ypred = np.where(np.array(data.ypred) > args.threshold, 1, 0)

    #get and print accuracy
    accuracy = accuracy_score(y, ypred)
    print("accuracy : %.2f%%" % (np.round(accuracy, decimals=4)*100))

    tn, fp, fn, tp = confusion_matrix(y, ypred).ravel()
    mt = np.array([[tp, fp],[fn, tn]])

    print(mt)
    print("false postive rate : %.2f%%" % ( round(fp / float(fp + tn), 4) * 100))
    print("false negative rate : %.2f%%" % ( round(fn / float(fn + tp), 4) * 100))

if __name__=='__main__':
    main()