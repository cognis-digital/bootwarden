using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace uefiscan {
    /// <summary>
    /// UEFI Firmware Parser for uefiscan tool.
    /// Audits firmware dumps for Secure Boot keys, unsigned modules, S3 vulns, and SMM threats.
    /// </summary>
    public static class FirmwareParser {
        // Known Secure Boot RSA-2048 public key (Microsoft default)
        private const string MS_RSA_2048 = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1bqH3xPv7fLz5Vd\n" +
            "sXJFmN4tY2pR8hN6cW3jKlM9oP1qE4rT6yU8iO0wZ5nA7bC3xD9eF2gH4jI5kL\n" +
            "6mN8oP0qR1sT2uV3wX4yZ5aB6cD7eE8fF9gG0hH1iI2jJ3kK4lL5mM6nN7oO8p\n" +
            "P9qQ0rR1sS2tT3uU4vV5wW6xX7yY8zZ9aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9k\n" +
            "K0lL1mM2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2xX3yY4zZ5aA6bB7cC8dD9eE0f\n" +
            "F1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7wW8xX9yY0zZ1a\n" +
            "A2bB3cC4dD5eE6fF7gG8hH9iI0jJ1kK2lL3mM4nN5oO6pP7qQ8rR9sS0tT1uU2v\n" +
            "V3wW4xX5yY6zZ7aA8bB9cC0dD1eE2fF3gG4hH5iI6jJ7kK8lL9mM0nN1oO2pP3q\n" +
            "Q4rR5sS6tT7uU8vV9wW0xX1yY2zZ3aA4bB5cC6dD7eE8fF9gG0hH1iI2jJ3kK4l\n" +
            "L5mM6nN7oO8pP9qQ0rR1sS2tT3uU4vV5wW6xX7yY8zZ9aA0bB1cC2dD3eE4fF5g\n" +
            "G6hH7iI8jJ9kK0lL1mM2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2xX3yY4zZ5aA6b\n" +
            "B7cC8dD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7w\n" +
            "W8xX9yY0zZ1aA2bB3cC4dD5eE6fF7gG8hH9iI0jJ1kK2lL3mM4nN5oO6pP7qQ8r\n" +
            "R9sS0tT1uU2vV3wW4xX5yY6zZ7aA8bB9cC0dD1eE2fF3gG4hH5iI6jJ7kK8lL9m\n" +
            "M0nN1oO2pP3qQ4rR5sS6tT7uU8vV9wW0xX1yY2zZ3aA4bB5cC6dD7eE8fF9gG0h\n" +
            "H1iI2jJ3kK4lL5mM6nN7oO8pP9qQ0rR1sS2tT3uU4vV5wW6xX7yY8zZ9aA0bB1c\n" +
            "C2dD3eE4fF5gG6hH7iI8jJ9kK0lL1mM2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2x\n" +
            "X3yY4zZ5aA6bB7cC8dD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3s\n" +
            "S4tT5uU6vV7wW8xX9yY0zZ1aA2bB3cC4dD5eE6fF7gG8hH9iI0jJ1kK2lL3mM4n\n" +
            "N5oO6pP7qQ8rR9sS0tT1uU2vV3wW4xX5yY6zZ7aA8bB9cC0dD1eE2fF3gG4hH5i\n" +
            "I6jJ7kK8lL9mM0nN1oO2pP3qQ4rR5sS6tT7uU8vV9wW0xX1yY2zZ3aA4bB5cC6d\n" +
            "D7eE8fF9gG0hH1iI2jJ3kK4lL5mM6nN7oO8pP9qQ0rR1sS2tT3uU4vV5wW6xX7y\n" +
            "Y8zZ9aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kK0lL1mM2nN3oO4pP5qQ6rR7sS8t\n" +
            "T9uU0vV1wW2xX3yY4zZ5aA6bB7cC8dD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9o\n" +
            "O0pP1qQ2rR3sS4tT5uU6vV7wW8xX9yY0zZ1aA2bB3cC4dD5eE6fF7gG8hH9iI0j\n" +
            "J1kK2lL3mM4nN5oO6pP7qQ8rR9sS0tT1uU2vV3wW4xX5yY6zZ7aA8bB9cC0dD1e\n" +
            "E2fF3gG4hH5iI6jJ7kK8lL9mM0nN1oO2pP3qQ4rR5sS6tT7uU8vV9wW0xX1yY2z\n" +
            "Z3aA4bB5cC6dD7eE8fF9gG0hH1iI2jJ3kK4lL5mM6nN7oO8pP9qQ0rR1sS2tT3u\n" +
            "U4vV5wW6xX7yY8zZ9aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kK0lL1mM2nN3oO4p\n" +
            "P5qQ6rR7sS8tT9uU0vV1wW2xX3yY4zZ5aA6bB7cC8dD9eE0fF1gG2hH3iI4jJ5k\n" +
            "K6lL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7wW8xX9yY0zZ1aA2bB3cC4dD5eE6f\n" +
            "F7gG8hH9iI0jJ1kK2lL3mM4nN5oO6pP7qQ8rR9sS0tT1uU2vV3wW4xX5yY6zZ7a\n" +
            "A8bB9cC0dD1eE2fF3gG4hH5iI6jJ7kK8lL9mM0nN1oO2pP3qQ4rR5sS6tT7uU8v\n" +
            "V9wW0xX1yY2zZ3aA4bB5cC6dD7eE8fF9gG0hH1iI2jJ3kK4lL5mM6nN7oO8pP9q\n" +
            "Q0rR1sS2tT3uU4vV5wW6xX7yY8zZ9aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kK0l\n" +
            "L1mM2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2xX3yY4zZ5aA6bB7cC8dD9eE0fF1g\n" +
            "G2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7wW8xX9yY0zZ1aA2b\n" +
            "B3cC4dD5eE6fF7gG8hH9iI0jJ1kK2lL3mM4nN5oO6pP7qQ8rR9sS0tT1uU2vV3w\n" +
            "W4xX5yY6zZ7aA8bB9cC0dD1eE2fF3gG4hH5iI6jJ7kK8lL9mM0nN1oO2pP3qQ4r\n" +
            "R5sS6tT7uU8vV9wW0xX1yY2zZ3aA4bB5cC6dD7eE8fF9gG0hH1iI2jJ3kK4lL5m\n" +
            "M6nN7oO8pP9qQ0rR1sS2tT3uU4vV5wW6xX7yY8zZ9aA0bB1cC2dD3eE4fF5gG6h\n" +
            "H7iI8jJ9kK0lL1mM2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2xX3yY4zZ5aA6bB7c\n" +
            "C8dD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7wW8x\n" +
            "X9yY0zZ1aA2bB3cC4dD5eE6fF7gG8hH9iI0jJ1kK2lL3mM4nN5oO6pP7qQ8rR9s\n" +
            "S0tT1uU2vV3wW4xX5yY6zZ7aA8bB9cC0dD1eE2fF3gG4hH5iI6jJ7kK8lL9mM0n\n" +
            "N1oO2pP3qQ4rR5sS6tT7uU8vV9wW0xX1yY2zZ3aA4bB5cC6dD7eE8fF9gG0hH1i\n" +
            "I2jJ3kK4lL5mM6nN7oO8pP9qQ0rR1sS2tT3uU4vV5wW6xX7yY8zZ9aA0bB1cC2d\n" +
            "D3eE4fF5gG6hH7iI8jJ9kK0lL1mM2nN3oO4pP5qQ6rR7sS8tT9uU0vV1wW2xX3y\n" +
            "Y4zZ5aA6bB7cC8dD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3sS4t\n" +
            "T5uU6vV7wW8xX9yY0zZ1aA2bB3cC4dD5eE6fF7gG8hH9iI0jJ1kK2lL3mM4nN5o\n" +
            "O6pP7qQ8rR9sS0tT1uU2vV3wW4xX5yY6zZ7aA8bB9cC0dD1eE2fF3gG4hH5iI6j\n" +
            "J7kK8lL9mM0nN1oO2pP3qQ4rR5sS6tT7uU8vV9wW0xX1yY2zZ3aA4bB5cC6dD7e\n" +
            "E8fF9gG0hH1iI2jJ3kK4lL5mM6nN7oO8pP9qQ0rR1sS2tT3uU4vV5wW6xX7yY8z\n" +
            "Z9aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kK0lL1mM2nN3oO4pP5qQ6rR7sS8tT9u\n" +
            "U0vV1wW2xX3yY4zZ5aA6bB7cC8dD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0p\n" +
            "P1qQ2rR3sS4tT5uU6vV7wW8xX9yY