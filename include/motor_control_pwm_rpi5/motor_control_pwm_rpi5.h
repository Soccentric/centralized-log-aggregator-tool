/**
 * @file motor_control_pwm_rpi5.h
 * @brief Main header file for the motor_control_pwm_rpi5 library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 * 
 * This header file provides the public interface for the motor_control_pwm_rpi5 library.
 * It contains the main class declaration and related type definitions.
 * 
 * @version 1.0
 * @date 2025-11-26
 * 
 * @details
 * The library implements a modern C++ design using the PIMPL (Pointer to Implementation)
 * idiom to provide binary compatibility and reduce compilation dependencies.
 * 
 * @note This library requires C++14 or later.
 * 
 * @example
 * @code
 * #include "motor_control_pwm_rpi5/motor_control_pwm_rpi5.h"
 * 
 * int main() {
 *     motor_control_pwm_rpi5::motorControlPwmRpi5 obj("example");
 *     obj.run();
 *     return 0;
 * }
 * @endcode
 */

#ifndef MOTOR_CONTROL_PWM_RPI5_H
#define MOTOR_CONTROL_PWM_RPI5_H

#include <string>
#include <memory>

/**
 * @namespace motor_control_pwm_rpi5
 * @brief Main namespace for motor_control_pwm_rpi5 library.
 * 
 * This namespace contains all public interfaces and classes provided by
 * the motor_control_pwm_rpi5 library. It encapsulates the library's functionality
 * and prevents naming conflicts with other libraries.
 */
namespace motor_control_pwm_rpi5 {

/**
 * @class motorControlPwmRpi5
 * @brief Primary class implementing the core functionality of motor_control_pwm_rpi5.
 * 
 * This class provides the main interface for using the motor_control_pwm_rpi5 library.
 * It implements the PIMPL pattern to hide implementation details and maintain
 * a stable ABI across library versions.
 * 
 * @details
 * The class manages internal resources through a private implementation class,
 * ensuring exception-safe resource management and enabling efficient copy semantics.
 * 
 * @invariant The internal implementation pointer (pimpl_) is always valid after
 *            construction and until destruction.
 * 
 * @thread_safety The class is not thread-safe. External synchronization is required
 *                for concurrent access.
 * 
 * @see run(), get_name()
 */
class motorControlPwmRpi5 {
public:
    /**
     * @brief Constructs a new motorControlPwmRpi5 object with the given name.
     * 
     * Initializes the object with a user-provided name string. The name is stored
     * internally and can be retrieved later using get_name().
     * 
     * @param name The name string to associate with this object. Must not be empty.
     * 
     * @throws std::invalid_argument if name is empty.
     * @throws std::bad_alloc if memory allocation fails during construction.
     * 
     * @pre name must be a valid non-empty string.
     * @post Object is fully initialized and ready for use.
     * 
     * @note The name parameter is passed by value to enable move semantics optimization.
     * 
     * @par Example:
     * @code
     * motor_control_pwm_rpi5::motorControlPwmRpi5 obj("MyName");
     * @endcode
     */
    explicit motorControlPwmRpi5(std::string name);

    /**
     * @brief Destroys the motorControlPwmRpi5 object and releases all resources.
     * 
     * The destructor ensures proper cleanup of all internal resources managed by
     * the implementation class. It is automatically called when the object goes
     * out of scope.
     * 
     * @note The destructor is declared to enable proper cleanup of the PIMPL pointer.
     * 
     * @exception noexcept This destructor does not throw exceptions.
     */
    ~motorControlPwmRpi5();

    /**
     * @brief Retrieves the name associated with this object.
     * 
     * Returns a copy of the name string that was provided during object construction.
     * The returned string is independent of the internal storage.
     * 
     * @return std::string A copy of the stored name.
     * 
     * @throws std::bad_alloc if string copy allocation fails.
     * 
     * @note This is a const member function and does not modify the object state.
     * 
     * @par Complexity:
     * O(n) where n is the length of the name string (due to copy operation).
     * 
     * @par Example:
     * @code
     * motor_control_pwm_rpi5::motorControlPwmRpi5 obj("Test");
     * std::string name = obj.get_name();  // name == "Test"
     * @endcode
     */
    std::string get_name() const;

    /**
     * @brief Executes the main functionality of the motor_control_pwm_rpi5 library.
     * 
     * This method performs the primary operation of this class, which includes
     * processing the stored name and generating output. The specific behavior
     * depends on the library's implementation details.
     * 
     * @throws std::runtime_error if execution encounters an error.
     * @throws std::bad_alloc if memory allocation is required and fails.
     * 
     * @pre Object must be properly initialized (constructor completed successfully).
     * @post The operation completes and any side effects are applied.
     * 
     * @note This method may produce output to stdout.
     * 
     * @par Example:
     * @code
     * motor_control_pwm_rpi5::motorControlPwmRpi5 obj("Example");
     * obj.run();  // Executes the main functionality
     * @endcode
     * 
     * @see get_name()
     */
    void run();

private:
    /**
     * @class Impl
     * @brief Private implementation class (PIMPL pattern).
     * 
     * This forward-declared class contains the actual implementation details
     * of motorControlPwmRpi5. It is hidden from the public interface to reduce
     * compilation dependencies and maintain ABI stability.
     * 
     * @note This class is only defined in the implementation file (.cpp).
     */
    class Impl;
    
    /**
     * @brief Pointer to the private implementation (PIMPL idiom).
     * 
     * This unique pointer manages the lifetime of the implementation class.
     * It provides automatic resource cleanup and prevents memory leaks.
     * 
     * @invariant pimpl_ is never null after construction completes.
     * 
     * @see Impl
     */
    std::unique_ptr<Impl> pimpl_;
};

} // namespace motor_control_pwm_rpi5

#endif // MOTOR_CONTROL_PWM_RPI5_H