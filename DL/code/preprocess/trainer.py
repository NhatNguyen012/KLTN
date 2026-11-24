#!/usr/bin/env python3
"""Multi-Task Trainer and Evaluator for BiLSTM Causal Host Model."""

from __future__ import annotations
import time
from typing import Dict, Any, Optional

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score


class MultiTaskLoss(nn.Module):
    """Weighted sum of Binary, Scenario, and MITRE Stage losses."""

    def __init__(
        self,
        weight_binary: float = 1.0,
        weight_scenario: float = 0.5,
        weight_stage: float = 0.8,
        pos_weight: Optional[float] = None
    ):
        super().__init__()
        self.w_bin = weight_binary
        self.w_sc = weight_scenario
        self.w_st = weight_stage

        pos_weight_tensor = torch.tensor([pos_weight]) if pos_weight else None
        self.criterion_bin = nn.BCEWithLogitsLoss(pos_weight=pos_weight_tensor)
        self.criterion_sc = nn.CrossEntropyLoss()
        self.criterion_st = nn.CrossEntropyLoss()

    def forward(
        self,
        outputs: Dict[str, torch.Tensor],
        targets: Dict[str, torch.Tensor]
    ) -> Dict[str, torch.Tensor]:
        loss_bin = self.criterion_bin(outputs["binary_logits"], targets["target_binary"])
        loss_sc = self.criterion_sc(outputs["scenario_logits"], targets["target_scenario"])
        loss_st = self.criterion_st(outputs["stage_logits"], targets["target_stage"])

        total_loss = self.w_bin * loss_bin + self.w_sc * loss_sc + self.w_st * loss_st

        return {
            "total_loss": total_loss,
            "loss_binary": loss_bin,
            "loss_scenario": loss_sc,
            "loss_stage": loss_st
        }


class MultiTaskTrainer:
    """Trains and evaluates BiLSTMCausalHostMultiTask."""

    def __init__(
        self,
        model: nn.Module,
        optimizer: torch.optim.Optimizer,
        criterion: Optional[MultiTaskLoss] = None,
        device: Optional[torch.device] = None
    ):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = model.to(self.device)
        self.optimizer = optimizer
        self.criterion = criterion or MultiTaskLoss()
        self.criterion.to(self.device)

    def train_epoch(self, dataloader: DataLoader) -> Dict[str, float]:
        self.model.train()
        total_loss = 0.0
        bin_loss = 0.0
        sc_loss = 0.0
        st_loss = 0.0
        steps = 0

        for batch in dataloader:
            token_ids = batch["token_ids"].to(self.device)
            offsets = batch["offsets"].to(self.device)
            batch_size = batch["batch_size"]

            targets = {
                "target_binary": batch["target_binary"].to(self.device),
                "target_scenario": batch["target_scenario"].to(self.device),
                "target_stage": batch["target_stage"].to(self.device),
            }

            self.optimizer.zero_grad()
            outputs = self.model(token_ids, offsets, batch_size)
            losses = self.criterion(outputs, targets)

            losses["total_loss"].backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()

            total_loss += losses["total_loss"].item()
            bin_loss += losses["loss_binary"].item()
            sc_loss += losses["loss_scenario"].item()
            st_loss += losses["loss_stage"].item()
            steps += 1

        return {
            "train_loss": total_loss / max(steps, 1),
            "train_loss_binary": bin_loss / max(steps, 1),
            "train_loss_scenario": sc_loss / max(steps, 1),
            "train_loss_stage": st_loss / max(steps, 1),
        }

    @torch.no_grad()
    def evaluate(self, dataloader: DataLoader) -> Dict[str, Any]:
        self.model.eval()
        total_loss = 0.0
        steps = 0

        all_bin_preds, all_bin_targets = [], []
        all_sc_preds, all_sc_targets = [], []
        all_st_preds, all_st_targets = [], []

        for batch in dataloader:
            token_ids = batch["token_ids"].to(self.device)
            offsets = batch["offsets"].to(self.device)
            batch_size = batch["batch_size"]

            targets = {
                "target_binary": batch["target_binary"].to(self.device),
                "target_scenario": batch["target_scenario"].to(self.device),
                "target_stage": batch["target_stage"].to(self.device),
            }

            outputs = self.model(token_ids, offsets, batch_size)
            losses = self.criterion(outputs, targets)

            total_loss += losses["total_loss"].item()
            steps += 1

            # Binary predictions
            probs_bin = torch.sigmoid(outputs["binary_logits"]).cpu().numpy()
            preds_bin = (probs_bin >= 0.5).astype(int)
            all_bin_preds.extend(preds_bin)
            all_bin_targets.extend(batch["target_binary"].numpy())

            # Multi-class predictions
            preds_sc = torch.argmax(outputs["scenario_logits"], dim=-1).cpu().numpy()
            all_sc_preds.extend(preds_sc)
            all_sc_targets.extend(batch["target_scenario"].numpy())

            preds_st = torch.argmax(outputs["stage_logits"], dim=-1).cpu().numpy()
            all_st_preds.extend(preds_st)
            all_st_targets.extend(batch["target_stage"].numpy())

        # Compute Metrics
        p_bin, r_bin, f1_bin, _ = precision_recall_fscore_support(
            all_bin_targets, all_bin_preds, average="binary", zero_division=0
        )
        _, _, f1_sc_macro, _ = precision_recall_fscore_support(
            all_sc_targets, all_sc_preds, average="macro", zero_division=0
        )
        _, _, f1_st_macro, _ = precision_recall_fscore_support(
            all_st_targets, all_st_preds, average="macro", zero_division=0
        )

        return {
            "val_loss": total_loss / max(steps, 1),
            "binary_precision": float(p_bin),
            "binary_recall": float(r_bin),
            "binary_f1": float(f1_bin),
            "scenario_f1_macro": float(f1_sc_macro),
            "stage_f1_macro": float(f1_st_macro),
        }
