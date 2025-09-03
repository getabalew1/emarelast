import React, { useState } from "react";
import { Mail, Phone, Users, ChevronDown, ChevronUp } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { services } from "../../data/Services";
import { motion } from "framer-motion";

export function Services() {
  const { user } = useAuth();
  const [expandedService, setExpandedService] = useState(null);

  const toggleService = (serviceId) => {
    setExpandedService(expandedService === serviceId ? null : serviceId);
  };

  const getHierarchyColor = (level) => {
    switch (level) {
      case 1:
      case 2:
        return "bg-gradient-to-r from-blue-600 to-blue-800";
      case 3:
      case 4:
        return "bg-gradient-to-r from-purple-600 to-purple-800";
      default:
        return "bg-gradient-to-r from-green-600 to-green-800";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-blue-800 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center"
          >
            <h1 className="text-4xl md:text-6xl font-bold mb-6">
              Our Services
            </h1>
            <p className="text-xl md:text-2xl text-blue-100 max-w-4xl mx-auto">
              Organizational structure of Debre Berhan University Services and
              responsibilities of each unit.
            </p>
          </motion.div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Services Structure */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100"
        >
          <h2 className="text-xl font-semibold text-gray-900 mb-6 text-center">
            Services Structure
          </h2>

          <div className="space-y-6">
            {[
              { range: [1, 2], label: "Executive Leadership" },
              { range: [3, 4], label: "Operational Leadership" },
              { range: [5, 10], label: "Service Units" },
            ].map((group, groupIndex) => (
              <div key={groupIndex} className="space-y-4">
                <h3 className="text-lg font-medium text-gray-800 border-b border-gray-200 pb-2">
                  {group.label}
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {services
                    .filter(
                      (service) =>
                        service.hierarchy >= group.range[0] &&
                        service.hierarchy <= group.range[1]
                    )
                    .map((service, index) => (
                      <motion.div
                        key={service.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: groupIndex * 0.1 + index * 0.05 }}
                        className="bg-gray-50 rounded-xl p-4 hover:shadow-md transition-all duration-200 cursor-pointer"
                        onClick={() => toggleService(service.id)}
                      >
                        <div className="flex items-center justify-between mb-3">
                          <div
                            className={`w-8 h-8 ${getHierarchyColor(
                              service.hierarchy
                            )} rounded-lg flex items-center justify-center text-white font-bold text-sm`}
                          >
                            {service.hierarchy}
                          </div>
                          {expandedService === service.id ? (
                            <ChevronUp className="w-5 h-5 text-gray-400" />
                          ) : (
                            <ChevronDown className="w-5 h-5 text-gray-400" />
                          )}
                        </div>

                        <h4 className="font-semibold text-gray-900 mb-2">
                          {service.nameEn}
                        </h4>

                        <p className="text-sm text-gray-600 mb-3">
                          {service.description}
                        </p>

                        <div className="flex items-center space-x-2 text-sm text-gray-500">
                          <Mail className="w-4 h-4" />
                          <span>{service.contact}</span>
                        </div>

                        {expandedService === service.id && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-4 pt-4 border-t border-gray-200"
                          >
                            <h5 className="font-medium text-gray-900 mb-2">
                              Responsibilities:
                            </h5>
                            <ul className="space-y-1">
                              {service.responsibilities.map(
                                (responsibility, idx) => (
                                  <li
                                    key={idx}
                                    className="text-sm text-gray-600 flex items-start"
                                  >
                                    <span className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-2 mr-2 flex-shrink-0"></span>
                                    {responsibility}
                                  </li>
                                )
                              )}
                            </ul>
                          </motion.div>
                        )}
                      </motion.div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Contact Information */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gradient-to-r from-blue-50 to-blue-100 rounded-2xl p-6"
        >
          <div className="text-center">
            <h3 className="text-xl font-semibold text-gray-900 mb-4">
              For More Information
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="flex items-center justify-center space-x-2">
                <Mail className="w-5 h-5 text-blue-600" />
                <span className="text-gray-700">info@dbu.edu.et</span>
              </div>
              <div className="flex items-center justify-center space-x-2">
                <Phone className="w-5 h-5 text-blue-600" />
                <span className="text-gray-700">+251-11-XXX-XXXX</span>
              </div>
              <div className="flex items-center justify-center space-x-2">
                <Users className="w-5 h-5 text-blue-600" />
                <span className="text-gray-700">12,547 Students</span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Admin Actions */}
        {(user?.role === "president" || user?.role === "student_din") && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6 }}
            className="bg-white rounded-xl p-6 shadow-sm border border-gray-100"
          >
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Administrative Actions
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <button className="p-4 border border-gray-200 rounded-lg hover:border-blue-300 hover:bg-blue-50 transition-colors text-left">
                <h4 className="font-medium text-gray-900 mb-2">
                  Update Service Information
                </h4>
                <p className="text-sm text-gray-600">
                  Edit service details and responsibilities
                </p>
              </button>

              <button className="p-4 border border-gray-200 rounded-lg hover:border-green-300 hover:bg-green-50 transition-colors text-left">
                <h4 className="font-medium text-gray-900 mb-2">
                  Assign Leadership
                </h4>
                <p className="text-sm text-gray-600">
                  Assign new leaders to services
                </p>
              </button>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}