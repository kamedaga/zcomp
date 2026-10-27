#include "runtime.h"

namespace Zcomp {
Runtime::Runtime()
{
    auto process = std::make_shared<Process_state>();
    process->address_space = std::make_shared<Address_space>();
    process->filesystem = std::make_shared<Fs_context>();
    // 64 KiBの入口スタックを起動側のCスタックに積まない。
    main_thread = std::make_unique<Thread_state>(process, process->pid);
}
}
