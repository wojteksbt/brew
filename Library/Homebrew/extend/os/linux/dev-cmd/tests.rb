# typed: strict
# frozen_string_literal: true

module OS
  module Linux
    module DevCmd
      module Tests
        extend T::Helpers

        requires_ancestor { Homebrew::DevCmd::Tests }

        private

        sig { params(bundle_args: T::Array[String]).returns(T::Array[String]) }
        def os_bundle_args(bundle_args)
          non_macos_bundle_args(bundle_args)
        end

        sig { params(files: T::Array[String]).returns(T::Array[String]) }
        def os_files(files)
          non_macos_files(files)
        end

        sig { void }
        def check_test_environment!
          super

          require "sandbox"
          with_env(HOMEBREW_SANDBOX_LINUX: "1") do
            return if ::Sandbox.available?

            with_env(HOMEBREW_TESTS: nil) do
              ::Sandbox.ensure_sandbox_installed!
            end

            return if ::Sandbox.available?
          end

          raise UsageError, "Linux tests require a working rootless Bubblewrap sandbox."
        end
      end
    end
  end
end

Homebrew::DevCmd::Tests.prepend(OS::Linux::DevCmd::Tests)
