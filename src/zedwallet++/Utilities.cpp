// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

//////////////////////////////////
#include <zedwallet++/Utilities.h>
//////////////////////////////////

#include <cmath>
#include <config/WalletConfig.h>
#include <fstream>
#include <iostream>
#include <utilities/ColouredMsg.h>
#include <utilities/PasswordContainer.h>
#include <utilities/String.h>

namespace ZedUtilities
{
    void confirmPassword(const std::shared_ptr<WalletBackend> walletBackend, const std::string msg)
    {
        const std::string currentPassword = walletBackend->getWalletPassword();

        /* Password container requires an rvalue, we don't want to wipe our current
           pass so copy it into a tmp string and std::move that instead */
        std::string tmpString = currentPassword;

        Tools::PasswordContainer pwdContainer(std::move(tmpString));

        while (!pwdContainer.read_and_validate(msg))
        {
            std::cout << WarningMsg("Incorrect password! Try again.") << std::endl;
        }
    }

    uint64_t getScanHeight()
    {
        std::cout << "\n";

        while (true)
        {
            std::cout << InformationMsg("What height would you like to begin ")
                      << InformationMsg("scanning your wallet from?") << "\n\n"
                      << "This can greatly speed up the initial wallet "
                      << "scanning process."
                      << "\n\n"
                      << "If you do not know the exact height, "
                      << "err on the side of caution so transactions do not "
                      << "get missed."
                      << "\n\n"
                      << InformationMsg("Hit enter for the sub-optimal default ") << InformationMsg("of zero: ");

            std::string stringHeight;

            std::getline(std::cin, stringHeight);

            /* Remove commas so user can enter height as e.g. 200,000 */
            Utilities::removeCharFromString(stringHeight, ',');

            if (stringHeight == "")
            {
                return 0;
            }

            try
            {
                return std::stoull(stringHeight);
            }
            catch (const std::out_of_range &)
            {
                std::cout << WarningMsg("Input is too large or too small!");
            }
            catch (const std::invalid_argument &)
            {
                std::cout << WarningMsg("Failed to parse height - input is not ") << WarningMsg("a number!")
                          << std::endl
                          << std::endl;
            }
        }
    }
    uint64_t getRewindToHeight(const std::shared_ptr<WalletBackend> walletBackend)
    {
        const WalletTypes::WalletStatus status = walletBackend->getStatus();
        const uint64_t defaultRewindHeight = status.walletBlockCount < 1000 ? 0 : status.walletBlockCount - 1000;

        std::cout << "\n";

        while (true)
        {
            std::cout << InformationMsg("What block height do you want to ") << InformationMsg("rewind your wallet to?")
                      << "\n\n"
                      << "All blocks after this height will be rescanned, "
                      << "use this command if you suspect a transaction "
                      << "has been missed by the sync process."
                      << "\n\n"
                      << InformationMsg("Hit enter for the default of ") << InformationMsg(defaultRewindHeight)
                      << InformationMsg(" (1000 blocks ago): ");

            std::string stringHeight;

            std::getline(std::cin, stringHeight);

            /* Remove commas so user can enter height as e.g. 200,000 */
            Utilities::removeCharFromString(stringHeight, ',');

            if (stringHeight == "")
            {
                return defaultRewindHeight;
            }

            try
            {
                return std::stoull(stringHeight);
            }
            catch (const std::out_of_range &)
            {
                std::cout << WarningMsg("Input is too large or too small!");
            }
            catch (const std::invalid_argument &)
            {
                std::cout << WarningMsg("Failed to parse height - input is not ") << WarningMsg("a number!")
                          << std::endl
                          << std::endl;
            }
        }
    }

    std::tuple<uint64_t, uint64_t> getScanRange()
    {

        uint64_t startHeight;
        uint64_t endHeight;

        std::cout << "\n";

        while (true)
        {
            std::cout << InformationMsg("What height would you like to begin ")
                      << InformationMsg("scanning your wallet from?") << "\n\n"
                      << "This can greatly speed up the initial wallet "
                      << "scanning process."
                      << "\n\n"
                      << "If you do not know the exact height, "
                      << "err on the side of caution so transactions do not "
                      << "get missed."
                      << "\n\n"
                      << InformationMsg("Hit enter for the sub-optimal default ") << InformationMsg("of zero: ");

            std::string stringStartHeight;

            std::getline(std::cin, stringStartHeight);

            /* Remove commas so user can enter height as e.g. 200,000 */
            Utilities::removeCharFromString(stringStartHeight, ',');

            if (stringStartHeight == "")
            {
                startHeight = 0;
                break;
            }

            try
            {
                startHeight = std::stoull(stringStartHeight);
                break;
            }
            catch (const std::out_of_range &)
            {
                std::cout << WarningMsg("Input is too large or too small!");
            }
            catch (const std::invalid_argument &)
            {
                std::cout << WarningMsg("Failed to parse height - input is not ") << WarningMsg("a number!")
                          << std::endl
                          << std::endl;
            }
        }

        while (true)
        {
            std::string defaultEndHeight;


            defaultEndHeight = std::to_string(startHeight + 1000);

            std::cout << "\n\n"
                      << InformationMsg("What height would you like to end ")
                      << InformationMsg("scanning your wallet from?") << "\n\n"
                      << InformationMsg("Hit enter for the default ") << InformationMsg("of ")
                      << InformationMsg(defaultEndHeight) << InformationMsg(": ");

            std::string stringEndHeight;

            std::getline(std::cin, stringEndHeight);
            Utilities::removeCharFromString(stringEndHeight, ',');

            if (stringEndHeight == "")
            {
                stringEndHeight = std::to_string(startHeight + 1000);
            }

            try
            {

              endHeight = std::stoull(stringEndHeight);
                
              if (startHeight > endHeight) 
              {
                  throw(startHeight);
              }        
              return
              {
                   startHeight, 
                   endHeight
              };
            }
            catch(uint64_t startHeight) {
                std::cout << WarningMsg("The end block height should be greater than the starting height you provided(") 
                << WarningMsg(std::to_string(startHeight)) 
                << WarningMsg(")");
            }
            catch (const std::out_of_range &)
            {
                std::cout << WarningMsg("Input is too large or too small!");
            }
            catch (const std::invalid_argument &)
            {
                std::cout << WarningMsg("Failed to parse height - input is not ") << WarningMsg("a number!")
                          << std::endl
                          << std::endl;
            }
        }
    }

} // namespace ZedUtilities