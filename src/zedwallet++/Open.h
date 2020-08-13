// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <walletbackend/WalletBackend.h>
#include <zedwallet++/ParseArguments.h>

std::shared_ptr<WalletBackend> openWallet(const ZedConfig &config);

std::shared_ptr<WalletBackend> importViewWallet(const ZedConfig &config);

std::shared_ptr<WalletBackend> importWalletFromKeys(const ZedConfig &config);

std::shared_ptr<WalletBackend> importWalletFromSeed(const ZedConfig &config);

std::shared_ptr<WalletBackend> createWallet(const ZedConfig &config);

Crypto::SecretKey getPrivateKey(const std::string outputMsg);

std::string getNewWalletFileName();

std::string getExistingWalletFileName(const ZedConfig &config);

std::string getWalletPassword(const bool verifyPwd, const std::string msg);

void viewWalletMsg();

void promptSaveKeys(const std::shared_ptr<WalletBackend> walletBackend);

const std::string getHeightMsg = "What height would you like to begin scanning your wallet from?\n\nThis can greatly speed up the initial wallet scanning process.\n\nIf you do not know the exact height, err on the side of caution so transactions do not get missed.\n\nHit enter for the sub-optimal default of zero: ";
