# typed: strict
# frozen_string_literal: true

require "fileutils"
require "env_config"

module OS
  module Linux
    module Sandbox
      extend T::Helpers

      requires_ancestor { ::Sandbox }

      BUBBLEWRAP = "bwrap"
      # `TIOCSCTTY` from `<asm-generic/ioctls.h>`; Ruby does not expose it.
      TIOCSCTTY = 0x540E
      READ_ONLY_PATHS = T.let(%w[
        /bin
        /etc
        /lib
        /lib64
        /opt
        /sbin
        /usr
      ].freeze, T::Array[String])
      private_constant :BUBBLEWRAP, :TIOCSCTTY, :READ_ONLY_PATHS

      sig { returns(T.nilable(::Pathname)) }
      def self.bubblewrap_executable
        PATH.new(ORIGINAL_PATHS, ENV.fetch("PATH")).each do |path|
          begin
            candidate = ::Pathname.new(File.expand_path(BUBBLEWRAP, path))
          rescue ArgumentError
            next
          end

          next if !candidate.file? || !candidate.executable?
          next if File.stat(candidate).setuid?

          return candidate
        end

        nil
      end

      sig { returns(::Pathname) }
      def self.bubblewrap_executable!
        bubblewrap_executable || raise("Bubblewrap is required to use the Linux sandbox.")
      end

      sig { void }
      def allow_write_temp_and_cache
        allow_write_path "/tmp"
        allow_write_path "/var/tmp"
        allow_write_path HOMEBREW_TEMP
        allow_write_path HOMEBREW_CACHE
      end

      sig { void }
      def allow_cvs
        cvspass = ::Pathname.new("#{Dir.home(ENV.fetch("USER"))}/.cvspass")
        allow_write path: cvspass, type: :literal if cvspass.exist?
      end

      sig { void }
      def allow_fossil
        [".fossil", ".fossil-journal"].each do |file|
          fossil_file = ::Pathname.new("#{Dir.home(ENV.fetch("USER"))}/#{file}")
          allow_write path: fossil_file, type: :literal if fossil_file.exist?
        end
      end

      module ClassMethods
        extend T::Helpers

        requires_ancestor { T.class_of(::Sandbox) }

        sig { returns(T.nilable(::Pathname)) }
        def bubblewrap_executable
          OS::Linux::Sandbox.bubblewrap_executable
        end

        sig { returns(::Pathname) }
        def bubblewrap_executable!
          OS::Linux::Sandbox.bubblewrap_executable!
        end

        sig { void }
        def ensure_sandbox_installed!
          return unless Homebrew::EnvConfig.sandbox_linux?
          # Never trigger a real install during `brew tests`.
          return if ENV["HOMEBREW_TESTS"]
          return if ENV["HOMEBREW_INSTALLING_BUBBLEWRAP"]
          return if bubblewrap_executable
          return unless CoreTap.instance.installed?

          require "formula"
          with_env(HOMEBREW_INSTALLING_BUBBLEWRAP: "1") do
            ::Formula["bubblewrap"].ensure_installed!(reason: "Linux sandboxing")
          end
        rescue FormulaUnavailableError
          nil
        end

        sig { returns(T::Boolean) }
        def available?
          return false unless Homebrew::EnvConfig.sandbox_linux?
          return false unless (bubblewrap = OS::Linux::Sandbox.bubblewrap_executable)
          # A setuid `bwrap` predates user namespaces and grants too much privilege.
          return false if File.stat(bubblewrap).setuid?

          system(
            bubblewrap.to_s,
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--ro-bind", "/", "/",
            "--proc", "/proc",
            "--dev", "/dev",
            "true",
            out: File::NULL,
            err: File::NULL
          ) == true
        end

        # `ioctl` request used to attach the sandboxed child to a controlling TTY.
        sig { returns(Integer) }
        def terminal_ioctl_request
          TIOCSCTTY
        end
      end

      private

      sig { params(args: T::Array[T.any(String, ::Pathname)], tmpdir: String).returns(T::Array[T.any(String, ::Pathname)]) }
      def sandbox_command(args, tmpdir)
        [OS::Linux::Sandbox.bubblewrap_executable!, *bubblewrap_args(tmpdir), "--", *args]
      end

      sig { params(tmpdir: String).returns(T::Array[String]) }
      def bubblewrap_args(tmpdir)
        args = T.let([
          "--unshare-user",
          "--unshare-ipc",
          "--unshare-pid",
          "--unshare-uts",
          "--unshare-cgroup-try",
          "--die-with-parent",
          "--new-session",
          "--dev", "/dev",
          "--proc", "/proc",
          "--dir", "/var"
        ], T::Array[String])
        args << "--unshare-net" if deny_all_network?

        ::Pathname.new(tmpdir).ascend.to_a.reverse_each do |path|
          next if path.root?

          args += ["--dir", path.to_s]
        end

        read_only_paths.each do |path|
          args += ["--ro-bind", path, path]
        end

        writable_paths.each do |path, type|
          prepare_writable_path(path, type)
          args += ["--bind", path, path]
        end

        denied_write_paths.each do |path|
          next unless File.exist?(path)

          args += ["--ro-bind", path, path]
        end

        args += ["--bind", tmpdir, tmpdir, "--chdir", tmpdir]

        args
      end

      sig { returns(T::Boolean) }
      def deny_all_network?
        profile.rules.any? do |rule|
          !rule.allow && rule.operation == "network*" && rule.filter.nil?
        end
      end

      sig { returns(T::Array[String]) }
      def read_only_paths
        (READ_ONLY_PATHS + [HOMEBREW_PREFIX.to_s, HOMEBREW_REPOSITORY.to_s] + profile.rules.filter_map do |rule|
          next if !rule.allow || !rule.operation.start_with?("file-read")
          next unless (filter = rule.filter)

          case filter.type
          when :literal, :subpath
            filter.path
          when :regex
            raise ArgumentError, "Linux sandbox does not support regex path filters: #{filter.path}"
          else
            raise ArgumentError, "Invalid path filter type: #{filter.type}"
          end
        end)
          .select { |path| File.exist?(path) }
          .uniq
      end

      sig { returns(T::Hash[String, Symbol]) }
      def writable_paths
        profile.rules.each_with_object({}) do |rule, paths|
          next if !rule.allow || !rule.operation.start_with?("file-write")
          next unless (filter = rule.filter)

          case filter.type
          when :literal, :subpath
            paths[filter.path] ||= filter.type
          when :regex
            raise ArgumentError, "Linux sandbox does not support regex path filters: #{filter.path}"
          else
            raise ArgumentError, "Invalid path filter type: #{filter.type}"
          end
        end
      end

      sig { returns(T::Array[String]) }
      def denied_write_paths
        profile.rules.filter_map do |rule|
          next if rule.allow || !rule.operation.start_with?("file-write")

          filter = rule.filter
          filter.path if filter && [:literal, :subpath].include?(filter.type)
        end.uniq
      end

      sig { params(path: String, type: Symbol).void }
      def prepare_writable_path(path, type)
        pathname = ::Pathname.new(path)
        return if pathname.exist?

        if type == :literal
          FileUtils.mkdir_p(pathname.dirname)
          FileUtils.touch(pathname)
        else
          FileUtils.mkdir_p(pathname)
        end
      end
    end
  end
end

Sandbox.prepend(OS::Linux::Sandbox)
Sandbox.singleton_class.prepend(OS::Linux::Sandbox::ClassMethods)
