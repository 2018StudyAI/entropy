import pandas as pd
import numpy as np
import pickle
import sklearn.ensemble as ske
from sklearn import model_selection
from sklearn import feature_selection, tree, linear_model
from sklearn.model_selection import train_test_split
from sklearn.externals import joblib
from sklearn.naive_bayes import GaussianNB
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument('-o', '--output', required="True")
parser.add_argument('-d', '--datadir', required="True")
args = parser.parse_args()

if not os.path.exists(args.datadir):
	parser.error("{} does not exist".format(args.datadir))
if not os.path.exists(args.output):
	os.mkdir(args.output)

def train():
	data = pd.read_csv(args.datadir, names=['hash', 'entropy', 'y'])
	X = data.drop(['hash', 'y'], axis=1).values
	y = data['y'].values

	# Feature selection using Trees Classifier
	fsel = ske.ExtraTreesClassifier().fit(X, y)
	model = feature_selection.SelectFromModel(fsel, prefit=True)
	X_new = model.transform(X)
	nb_features = X_new.shape[1]

	X_train, X_test, y_train, y_test = model_selection.train_test_split(X_new, y ,test_size=0.2)

	features = []
	# XXX : take care of the feature order
	for f in sorted(np.argsort(fsel.feature_importances_)[::-1][:nb_features]):
	    features.append(data.columns[2+f])

	#Algorithm comparison
	algorithms = {
		"DecisionTree": tree.DecisionTreeClassifier(max_depth=10),
		"RandomForest": ske.RandomForestClassifier(n_estimators=10),
		"GradientBoosting": ske.GradientBoostingClassifier(n_estimators=10),
		"AdaBoost": ske.AdaBoostClassifier(n_estimators=10),
		"GNB": GaussianNB()
	    }

	results = {}
	for algo in algorithms:
	    clf = algorithms[algo]
	    clf.fit(X_train, y_train)
	    score = clf.score(X_test, y_test)
	    print("%s : %f %%" % (algo, score*100))
	    results[algo] = score
		
	#choose best algorithm
	winner = max(results, key=results.get)

	#save model and features
	joblib.dump(algorithms[winner], os.path.join(args.output, 'classifier.pkl'))
	#open(os.path.join(args.output, 'features.pkl'), 'w').write(pickle.dumps(features))

def main():
	train()

if __name__=='__main__':
	main()