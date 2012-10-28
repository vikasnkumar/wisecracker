/*
    Wisecracker: A cryptanalysis framework
    Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
 * Copyright: 2011 - 2012. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 27th Oct 2012
 * Software: WiseCracker
 */
#ifndef __WISECRACKER_CPPWRAPPER_H__
#define __WISECRACKER_CPPWRAPPER_H__

#ifdef WC_CXX_STRING
#include <string>
#endif
#ifdef WC_CXX_STDEXCEPT
#include <stdexcept>
#endif

namespace wc {

	class Executor;

	class WCDLL CallbackInterface {
	private:
		uint32_t _max_devices;
		wc_devtype_t _devtype;
		const Executor *_executor;
		friend class Executor;
	public:
		struct Range {
			uint64_t start;
			uint64_t end;
		};
		inline void set(uint32_t max_devices, wc_devtype_t devtype)
		{
			_max_devices = max_devices;
			_devtype = devtype;
			_executor = NULL;
		}
		CallbackInterface()
		{
			set(0, WC_DEVTYPE_ANY);
		}
		CallbackInterface(uint32_t max_devices, wc_devtype_t devtype)
		{
			set(max_devices, devtype);
		}
		virtual ~CallbackInterface()
		{
		}
		
		const Executor *get_executor() const
		{
			return _executor;
		}

		inline uint32_t max_devices() const
		{
			return _max_devices;
		}
		inline wc_devtype_t device_type() const
		{
			return _devtype;
		}
		virtual wc_err_t on_start()
		{
			return WC_EXE_OK;
		}
		virtual wc_err_t on_finish()
		{
			return WC_EXE_OK;
		}

		virtual wc_err_t get_code(std::string &code) = 0;

		virtual void get_build_options(std::string &options)
		{
		}
		virtual void on_code_compile(bool success)
		{
		}

		virtual uint64_t get_num_tasks() = 0;

		virtual uint32_t get_task_multiplier()
		{
			return 1;
		}
		virtual wc_err_t get_global_data(wc_data_t &gdata)
		{
			gdata.ptr = NULL;
			gdata.len = 0;
			return WC_EXE_OK;
		}
		virtual void free_global_data(wc_data_t &gdata) = 0;

		virtual wc_err_t on_receive_global_data(const wc_data_t &gdata)
		{
			return WC_EXE_OK;
		}
		virtual wc_err_t on_device_start(wc_cldev_t &dev, uint32_t devindex,
											const wc_data_t &gdata)
		{
			return WC_EXE_OK;
		}
		virtual wc_err_t on_device_finish(wc_cldev_t &dev, uint32_t devindex,
											const wc_data_t &gdata)
		{
			return WC_EXE_OK;
		}
		virtual wc_err_t on_device_range_exec(wc_cldev_t &dev,
												uint32_t devindex,
												const wc_data_t &gdata,
												Range &range,
												cl_event *outevent) = 0;
		virtual wc_err_t on_device_range_done(wc_cldev_t &dev,
												uint32_t devindex,
												const wc_data_t &gdata,
												Range &range,
												wc_data_t &results)
		{
			results.ptr = NULL;
			results.len = 0;
			return WC_EXE_OK;
		}
		virtual wc_err_t on_receive_range_results(Range &range,
												wc_err_t range_error,
												const wc_data_t &results)
		{
			return WC_EXE_OK;
		}
		void progress(float percent)
		{
		}

	};

	class WCDLL Executor {
		public:
			explicit Executor(int *argc, char ***argv);
			~Executor();
			// install the callbacks to run
			wc_err_t setup(CallbackInterface *cb);
			// run the executor
			wc_err_t run();
			// get the number of systems
			int num_systems() const;
			// get the current id of the system
			int my_id() const;
			// check if you're the master or slave
			inline bool is_master() const
			{
				return (my_id() == 0);
			}
			// get the total number of tasks setup in the Callbacks
			uint64_t num_tasks() const;
			// get the number of OpenCL devices in the current system
			uint32_t num_system_devices() const;
			// print info of current implementation
			void dump() const;
		private:
			struct Implementation;
			Implementation *_impl;
			// no copying
			Executor(const Executor &);
			Executor &operator=(const Executor &);
	};


} // end of namespace wc

#endif // __WISECRACKER_CPPWRAPPER_H__
