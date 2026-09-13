import argparse
import os

import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_curve, roc_curve
from pygod.pygod.detector import GAE, DOMINANT
import torch
from torch_geometric.data import DataLoader
from pygod.pygod.metric.metric import eval_roc_auc
from tqdm import tqdm
from utils import CustomGraphDataset
from pygod.pygod.utils.score_converter import to_graph_score


def create_dataloader(clients, base_train, base_test, labels):
    graphs_train = []
    graphs_test = []
    for c in clients:
        base_train_c = base_train.replace("client", c)
        base_test_c = base_test.replace("client", c)
        for root, dirs, files in os.walk(base_train_c):
            if "/benign" in root:
                graphs_train.extend([f"{root}/{f}" for f in sorted(files)[:1]])

        for root, dirs, files in os.walk(base_test_c):
            if "/eval" in root:
                graphs_test.extend([f"{root}/{f}" for f in sorted(files)])

    print("Train dataset...")
    dataset_train = CustomGraphDataset(graphs_train)
    print("Test dataset...")
    dataset_test = CustomGraphDataset(graphs_test, clients, labels)

    print(len(dataset_train), len(dataset_test))

    dataloader_train = DataLoader(
        dataset_train.data_list, batch_size=len(dataset_train), shuffle=True
    )
    dataloader_test = DataLoader(dataset_test.data_list, batch_size=1, shuffle=False)
    return dataloader_train, dataloader_test, dataset_test.name_graph


def load_gae(name, num_layers):
    model = torch.load(f"{name}.pth")
    return model


def train_gae(name, dataloader_train, epoch, num_layers):

    detector = GAE(
        epoch=epoch,
        num_layers=num_layers,
        verbose=3,
        recon_s=False,
    )
    print("Train model...")
    for data in dataloader_train:
        detector.fit(data)

    torch.save(detector, f"{name}.pth")

    return detector


def eval_gae(model, dataloader_test):

    scores = []
    labels = []
    for data in tqdm(dataloader_test):
        _, score = model.predict(
            data, return_pred=True, return_score=True, return_conf=False
        )
        scores.append(to_graph_score(score.cpu()))
        labels.append(max(data.y.cpu()))
    return labels, scores


def roc(labels, scores):
    auc_score = eval_roc_auc(labels, scores)
    pre, rec, ths = precision_recall_curve(labels, scores)
    f1s = []
    for k, i in enumerate(pre):
        if (i + rec[k]) == 0:
            f1s.append(0)
        else:
            f1 = (2 * i * rec[k]) / (i + rec[k])
            f1s.append(f1)
    print(f1s)
    th = int(np.argmax(f1s))
    print(th)
    print("AUC :", auc_score)
    print("Precision: ", pre[th], "\nRecall: ", rec[th], "\nF1-score: ", f1s[th])
    predictions = (scores >= ths[th]).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions).ravel()
    print("TN: ", tn, "\nFP: ", fp, "\nFN: ", fn, "\nTP: ", tp)
    return predictions


def results_details(label, prediction, name_graph):
    assert len(label) == len(prediction)
    TP, FP, TN, FN = [], [], [], []
    GT = []
    for k, i in enumerate(label):
        if prediction[k] == i and i == 1:
            TP.append(name_graph[k])
            GT.append(name_graph[k])
        elif prediction[k] != i and i == 1:
            FN.append(name_graph[k])
            GT.append(name_graph[k])
        elif prediction[k] != i and i == 0:
            FP.append(name_graph[k])
        else:
            TN.append(name_graph[k])
    print(f"\nGT: {GT}\n\nTP: {set(TP)}\nFP: {set(FP)}\nFN: {set(FN)}\n")
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and eval GAE.")
    parser.add_argument(
        "-test",
        "--test",
        dest="base_test",
        action="store",
        default="/evaluation/",
        help="path to you tested data",
    )
    parser.add_argument(
        "-train",
        "--train",
        dest="base_train",
        action="store",
        default="/benign/",
        help="path to you benign data",
    )
    parser.add_argument(
        "-n",
        "--name",
        dest="name",
        action="store",
        default="Pygod/model_corrected_051",
        help="name of your model",
    )
    parser.add_argument(
        "-e",
        "--epoch",
        dest="epoch",
        action="store",
        default=15,
        type=int,
        help="number of epochs to train GAE",
    )
    parser.add_argument(
        "-l",
        "--layers",
        dest="layers",
        action="store",
        default=3,
        type=int,
        help="number of layers",
    )
    parser.add_argument(
        "-red",
        "--red",
        dest="labels",
        action="store",
        default="Labels/events/our/corrected/labels.csv",
        help="csv file that containt labels event",
    )
    parser.add_argument(
        "-hos",
        "--host",
        dest="h",
        action="store",
        default="",
        help="host",
    )
    args = parser.parse_args()

    clients = [args.h]
    clients = ["051"]
    print(clients)
    base = "Pygod/graphs/client/corrected/"
    base_train = base + args.base_train
    base_test = base + args.base_test

    dataloader_train, dataloader_test, test_name_graph = create_dataloader(
        clients, base_train, base_test, args.labels
    )
    model = load_gae(args.name, args.layers)
    # model = train_gae(args.name, dataloader_train, args.epoch, args.layers)
    labels, scores = eval_gae(model, dataloader_test)
    prediction = roc(labels, scores)
    results_details(labels, prediction, test_name_graph)
