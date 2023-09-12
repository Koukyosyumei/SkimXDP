import pandas as pd
import pickle
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

if __name__ == "__main__":
    df = pd.read_csv("demo/sampled-attack-simulation-alert.csv")
    X = df.drop("alert", axis=1)
    y = df["alert"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.33, random_state=42
    )

    clf = DecisionTreeClassifier(random_state=0)
    clf.fit(X_train, y_train)
    print("AUC of DecisionTree: ", roc_auc_score(
        y_test, clf.predict_proba(X_test)[:, 1]))

    with open("model/tree.pkl", "wb") as f:
        pickle.dump((clf, X.columns.tolist()), f)

    clf = LogisticRegression(random_state=0)
    clf.fit(X_train, y_train)
    print("AUC of LogisticRegression: ", roc_auc_score(
        y_test, clf.predict_proba(X_test)[:, 1]))

    with open("model/lr.pkl", "wb") as f:
        pickle.dump((clf, X.columns.tolist()), f)

    clf = MLPClassifier(hidden_layer_sizes=(
        10, 5), random_state=1, max_iter=50)
    clf.fit(X_train, y_train)
    clf.fit(X_train, y_train)
    print("AUC of MLP: ", roc_auc_score(
        y_test, clf.predict_proba(X_test)[:, 1]))

    with open("model/mlp.pkl", "wb") as f:
        pickle.dump((clf, X.columns.tolist()), f)
