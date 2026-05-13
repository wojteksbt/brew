# typed: false
# frozen_string_literal: true

require "cmd/shared_examples/args_parse"
require "dev-cmd/tests"

RSpec.describe Homebrew::DevCmd::Tests do
  it_behaves_like "parseable arguments"

  describe "#check_test_environment!", :needs_linux do
    subject(:tests) { described_class.new([]) }

    before do
      require "extend/os/linux/dev-cmd/tests"
      require "sandbox"
    end

    it "raises when the Linux sandbox is unavailable" do
      allow(Sandbox).to receive(:available?).and_return(false)
      expect(Sandbox).to receive(:ensure_sandbox_installed!) do
        expect(ENV.fetch("HOMEBREW_TESTS", nil)).to be_nil
      end

      expect { tests.send(:check_test_environment!) }
        .to raise_error(UsageError, "Linux tests require a working rootless Bubblewrap sandbox.")
    end

    it "returns after installing the Linux sandbox" do
      allow(Sandbox).to receive(:available?).and_return(false, true)
      expect(Sandbox).to receive(:ensure_sandbox_installed!)

      expect { tests.send(:check_test_environment!) }.not_to raise_error
    end

    it "probes sandbox availability with Linux sandboxing enabled" do
      allow(Sandbox).to receive(:available?) { ENV["HOMEBREW_SANDBOX_LINUX"] == "1" }
      expect(Sandbox).not_to receive(:ensure_sandbox_installed!)

      with_env(HOMEBREW_SANDBOX_LINUX: nil) do
        expect { tests.send(:check_test_environment!) }.not_to raise_error
      end
    end
  end
end
