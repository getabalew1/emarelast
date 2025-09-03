import React from "react";
import { Users, Target, Heart, Globe, Lightbulb, Shield } from "lucide-react";
import { motion } from "framer-motion";
import "../../index.css"; // Make sure this file actually exists

export const About = () => {
  const values = [
    {
      icon: <Heart className="w-10 h-10 mb-4 text-red-500" />,
      title: "Passion",
      description: "We are driven by a deep passion to serve and uplift our student community.",
    },
    {
      icon: <Globe className="w-10 h-10 mb-4 text-green-500" />,
      title: "Unity",
      description: "We believe in the strength of unity and the power of collective effort.",
    },
    {
      icon: <Shield className="w-10 h-10 mb-4 text-blue-500" />,
      title: "Integrity",
      description: "We uphold the highest standards of integrity and transparency.",
    },
    {
      icon: <Lightbulb className="w-10 h-10 mb-4 text-yellow-500" />,
      title: "Innovation",
      description: "We embrace innovation to find better ways to serve and lead.",
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-blue-600 to-blue-800 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold mb-6">About Us</h1>
            <p className="text-xl md:text-2xl text-blue-100 max-w-4xl mx-auto">
              Learn more about who we are and what we stand for as your Student Union.
            </p>
          </motion.div>
        </div>
      </section>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        {/* Mission Statement */}
        <motion.div
          className="mb-16 bg-white rounded-2xl p-8 shadow-sm"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <h3 className="text-2xl font-semibold mb-4 text-gray-900">Our Mission</h3>
          <p className="text-gray-600 leading-relaxed text-lg">
            To empower and represent the student body of DBU, fostering an inclusive and dynamic campus
            environment where every voice is heard, valued, and acted upon.
          </p>
        </motion.div>

        {/* Vision Statement */}
        <motion.div
          className="mb-16 bg-white rounded-2xl p-8 shadow-sm"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
        >
          <h3 className="text-2xl font-semibold mb-4 text-gray-900">Our Vision</h3>
          <p className="text-gray-600 leading-relaxed text-lg">
            To be a leading student union recognized for effective leadership, impactful initiatives,
            and a relentless commitment to student success and welfare.
          </p>
        </motion.div>

        {/* Core Values */}
        <motion.div
          className="mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
        >
          <h3 className="text-2xl font-semibold mb-8 text-center text-gray-900">Our Core Values</h3>
          <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
            {values.map((value, index) => (
              <motion.div
                key={index}
                className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 text-center hover:shadow-lg transition-shadow"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: index * 0.1 }}
              >
                {value.icon}
                <h4 className="text-xl font-semibold mb-2 text-gray-900">{value.title}</h4>
                <p className="text-gray-600">{value.description}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Leadership */}
        <motion.div
          className="text-center bg-white rounded-2xl p-8 shadow-sm"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.8 }}
        >
          <h3 className="text-2xl font-semibold mb-4 text-gray-900">Our Leadership</h3>
          <p className="text-gray-600 leading-relaxed text-lg">
            Meet the dedicated team behind the DBU Student Union — passionate individuals working
            tirelessly to create a better campus for everyone.
          </p>
        </motion.div>
      </div>
    </div>
  );
};
