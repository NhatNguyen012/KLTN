#!/usr/bin/env python3
"""Persist one stratified random split shared by RF, XGBoost and LightGBM."""
from ML.code.preprocess.stratified_pipeline import split_main

if __name__ == '__main__':
    raise SystemExit(split_main())
