#include "AliveCheckTimer.h"

#if defined(__XTENSA__)
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
#endif //defined(__XTENSA__)

/**
 * Initialize and starts the alive check timer
 */
void AliveCheckTimer::startTimer() {
    if(disabled == false) {
        resetTimer();
        timerThreads.push_back(std::thread(&AliveCheckTimer::waitForResponse, this));
    }
}

/**
 * Checks if a timeout occured
 */
void AliveCheckTimer::waitForResponse() {
    while(!disabled) {
        double secondsPassed = (clock() - startTime) / CLOCKS_PER_SEC;
        if(secondsPassed >= maxSeconds) {
            disabled = true;
            timeout = true;
            cb();
        }
        #if defined(__XTENSA__)
            vTaskDelay(1);
        #elif defined(__linux__) && !defined(__XTENSA__)
            const struct timespec ten_milliseconds = {
            .tv_sec = 0,
            .tv_nsec = 10000000
            }
            nanosleep(&ten_milliseconds, NULL);
        #endif
    }
}

/**
 * Resets the timer to the current time
 */
void AliveCheckTimer::resetTimer() {
    startTime = clock();
    active = true;
}

/**
 * Sets the maximum seconds to wait till a timeout occurs
 * @param seconds   seconds till timeout
 */
void AliveCheckTimer::setTimer(uint16_t seconds) {
    maxSeconds = seconds;
}

AliveCheckTimer::~AliveCheckTimer() {
    disabled = true;
    if(timerThreads.size() > 0) {
        timerThreads.at(0).join();
    }
}
